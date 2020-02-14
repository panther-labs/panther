package processor

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"bufio"
	"io"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/resources/client/operations"
	api "github.com/panther-labs/panther/api/gateway/resources/models"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const maxBackoffSeconds = 30

// Handle is the entry point for the event stream analysis.
//
// Do not make any assumptions about the correctness of the incoming data.
func Handle(batch *events.SQSEvent) error {
	// De-duplicate all updates and deletes before delivering them.
	// At most one change will be reported per resource (update or delete).
	//
	// For example, if a bucket is Deleted, Created, then Modified all in this batch,
	// we will send a single update request (i.e. queue a bucket scan).
	changes := make(map[string]*resourceChange, len(batch.Records)) // keyed by resourceID

	// Get the most recent integrations to map Account ID to IntegrationID
	if err := refreshAccounts(); err != nil {
		return err
	}

	// Using gjson to get only the fields we need is > 10x faster than running json.Unmarshal multiple times
	for _, record := range batch.Records {
		switch gjson.Get(record.Body, "Type").Str {
		case "Notification": // sns wrapped message
			// Three possibilities:
			// Raw CloudTrail (detail)
			// S3Event Notification (records)
			// CloudTrail Notification (s3Bucket + s3ObjectKey list)
			zap.L().Debug("processing SNS message")
			message := gjson.Get(record.Body, "Message").Str
			err := processSNS(message, changes, gjson.Get(record.Body, "TopicArn").Str)
			if err != nil {
				zap.L().Error("error processing SNS message", zap.Error(errors.WithStack(err)))
			}
		case "": // raw CloudTrail data from CWE -> SNS -> SQS
			zap.L().Debug("processing raw CloudTrail")
			err := processCloudTrail(gjson.Get(record.Body, "detail"), changes)
			if err != nil {
				zap.L().Error("error processing raw CloudTrail", zap.Error(errors.WithStack(err)))
			}
		case "SubscriptionConfirmation": // sns confirmation message
			topicArn, err := arn.Parse(gjson.Get(record.Body, "TopicArn").Str)
			if err != nil {
				zap.L().Warn("invalid confirmation arn", zap.Error(err))
				continue
			}

			token := gjson.Get(record.Body, "Token").Str
			if err = handleSnsConfirmation(topicArn, &token); err != nil {
				return err
			}
		default: // Unexpected type
			zap.L().Warn("unexpected SNS record type",
				zap.String("type", gjson.Get(record.Body, "Type").Str),
				zap.String("body", record.Body),
			)
			continue
		}
	}
	return submitChanges(changes)
}

func bulkProcessCloudTrail(cloudtrails string, changes map[string]*resourceChange) {
	// Wrapper for processing multiple CloudTrail logs at once
	for _, cloudtrail := range gjson.Get(cloudtrails, "Records").Array() {
		err := processCloudTrail(cloudtrail, changes)
		if err != nil {
			zap.L().Error("error while bulk processing CloudTrail", zap.Error(err))
		}
	}
}

func processCloudTrail(cloudtrail gjson.Result, changes map[string]*resourceChange) error {
	if !cloudtrail.Exists() {
		return errors.WithStack(errors.New("dropping bad event"))
	}

	// this event potentially requires a change to some number of resources
	for _, summary := range classifyCloudTrailLog(cloudtrail) {
		zap.L().Info("resource change required", zap.Any("changeDetail", summary))
		// Prevents the following from being de-duped mistakenly:
		//
		// - Resources with the same ID in different regions (different regions)
		// - Service scans in the same region (different resource types)
		// - Resources with the same type in the same region (different resource IDs)
		key := summary.ResourceID + summary.ResourceType + summary.Region
		if entry, ok := changes[key]; !ok || summary.EventTime > entry.EventTime {
			changes[key] = summary // the newest event for this resource we've seen so far
		}
	}
	return nil
}

func processSNS(message string, changes map[string]*resourceChange, topicArn string) error {
	detail := gjson.Get(message, "detail")
	if detail.Exists() {
		zap.L().Debug("SNS message was wrapped CloudTrail, processing CloudTrail")
		return processCloudTrail(detail, changes)
	}

	// For either of the remaining cases way we will need to download some S3 objects
	var s3Objects []*sources.S3ObjectInfo
	records := gjson.Get(message, "Records")
	if records.Exists() {
		zap.L().Debug("SNS message was an S3 Event Notification")
		records.ForEach(func(_, bucket gjson.Result) bool {
			s3Objects = append(s3Objects, &sources.S3ObjectInfo{
				S3Bucket:    bucket.Get("s3.bucket.name").Str,
				S3ObjectKey: bucket.Get("s3.object.key").Str,
			})
			return true
		})
		processS3Download(s3Objects, changes, topicArn)
		return nil
	}

	bucket := gjson.Get(message, "s3Bucket")
	if bucket.Exists() {
		zap.L().Debug("SNS message was a CloudTrail Notification")
		bucketStr := bucket.Str
		keys := gjson.Get(message, "s3ObjectKey").Array()
		for _, key := range keys {
			s3Objects = append(s3Objects, &sources.S3ObjectInfo{
				S3Bucket:    bucketStr,
				S3ObjectKey: key.Str,
			})
		}
		processS3Download(s3Objects, changes, topicArn)
		return nil
	}

	return errors.New("unable to determine SNS message type")
}

func processS3Download(objects []*sources.S3ObjectInfo, changes map[string]*resourceChange, topicArn string) {
	zap.L().Debug("processing CloudTrail stored in S3, initiating downloads")
	for _, object := range objects {
		input, err := sources.ReadS3Object(object, topicArn)
		if err != nil {
			zap.L().Error("error setting up s3 connection", zap.Error(errors.WithStack(err)))
			continue
		}

		stream := bufio.NewReader(input.Reader)
		for {
			var line string
			line, err = stream.ReadString('\n')
			if err != nil {
				if err == io.EOF { // we are done
					err = nil
					bulkProcessCloudTrail(line, changes)
				}
				break
			}
			bulkProcessCloudTrail(line, changes)
		}
		if err != nil {
			zap.L().Error("failed to process S3 download", zap.Error(errors.WithStack(err)))
		}
	}
}

func submitChanges(changes map[string]*resourceChange) error {
	var deleteRequest api.DeleteResources
	requestsByDelay := make(map[int64]*poller.ScanMsg)

	for _, change := range changes {
		if change.Delete {
			deleteRequest.Resources = append(deleteRequest.Resources, &api.DeleteEntry{
				ID: api.ResourceID(change.ResourceID),
			})
		} else {
			// Possible configurations:
			// ID = “”, region =“”:				Account wide service scan; use sparingly
			// ID = “”, region =“west”:			Region wide service scan
			// ID = “abc-123”, region =“”:		Single resource scan
			// ID = “abc-123”, region =“west”:	Undefined, treated as single resource scan
			var resourceID *string
			var region *string
			if change.ResourceID != "" {
				resourceID = &change.ResourceID
			}
			if change.Region != "" {
				region = &change.Region
			}

			if _, ok := requestsByDelay[change.Delay]; !ok {
				requestsByDelay[change.Delay] = &poller.ScanMsg{}
			}

			// Group all changes together by their delay time. This will maintain our ability to
			// group together changes that happened close together in time. I imagine in cases where
			// we set a delay it will be a fairly uniform delay.
			requestsByDelay[change.Delay].Entries = append(requestsByDelay[change.Delay].Entries, &poller.ScanEntry{
				AWSAccountID:     &change.AwsAccountID,
				IntegrationID:    &change.IntegrationID,
				Region:           region,
				ResourceID:       resourceID,
				ResourceType:     &change.ResourceType,
				ScanAllResources: aws.Bool(false),
			})
		}
	}

	// Send deletes to resources-api
	if len(deleteRequest.Resources) > 0 {
		zap.L().Info("deleting resources", zap.Any("deleteRequest", &deleteRequest))
		_, err := apiClient.Operations.DeleteResources(
			&operations.DeleteResourcesParams{Body: &deleteRequest, HTTPClient: httpClient})

		if err != nil {
			zap.L().Error("resource deletion failed", zap.Error(err))
			return err
		}
	}

	if len(requestsByDelay) > 0 {
		batchInput := &sqs.SendMessageBatchInput{QueueUrl: &queueURL}
		// Send resource scan requests to the poller queue
		for delay, request := range requestsByDelay {
			zap.L().Info("queueing resource scans", zap.Any("updateRequest", request))
			body, err := jsoniter.MarshalToString(request)
			if err != nil {
				zap.L().Error("resource queueing failed: json marshal", zap.Error(err))
				return err
			}

			batchInput.Entries = append(batchInput.Entries, &sqs.SendMessageBatchRequestEntry{
				Id:           aws.String(strconv.FormatInt(delay, 10)),
				MessageBody:  aws.String(body),
				DelaySeconds: aws.Int64(delay),
			})
		}

		if err := sqsbatch.SendMessageBatch(sqsClient, maxBackoffSeconds, batchInput); err != nil {
			return err
		}
	}

	return nil
}
