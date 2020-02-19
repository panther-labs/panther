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
	"compress/gzip"
	"io"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/s3"
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
	"github.com/panther-labs/panther/pkg/oplog"
)

const maxBackoffSeconds = 30

// Handle is the entry point for the event stream analysis.
//
// Do not make any assumptions about the correctness of the incoming data.
func Handle(lc *lambdacontext.LambdaContext, batch *events.SQSEvent) (err error) {
	operation := oplog.NewManager("cloudsec", "aws_event_processor").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("numEvents", len(batch.Records)))
	}()

	// De-duplicate all updates and deletes before delivering them.
	// At most one change will be reported per resource (update or delete).
	//
	// For example, if a bucket is Deleted, Created, then Modified all in this batch,
	// we will send a single update request (i.e. queue a bucket scan).
	changes := make(map[string]*resourceChange, len(batch.Records)) // keyed by resourceID

	// Get the most recent integrations to map Account ID to IntegrationID
	if err = refreshAccounts(); err != nil {
		return err
	}

	// Using gjson to get only the fields we need is > 10x faster than running json.Unmarshal multiple times
	//
	// Since we don't want one bad notification to lose us the rest, we log failures and continue.
	for _, record := range batch.Records {
		// SNS raw message delivery of CloudTrail
		detail := gjson.Get(record.Body, "detail")
		if detail.Exists() {
			zap.L().Debug("processing raw CloudTrail")
			err := processCloudTrail(detail, changes)
			if err != nil {
				zap.L().Error("error processing raw CloudTrail", zap.Error(errors.WithStack(err)))
			}
			continue
		}

		// This case is checking for a notification from the log processor that there is newly processed CloudTrail logs
		results := gjson.GetMany(record.Body, "s3Bucket", "s3ObjectKey")
		if results[0].Exists() && results[1].Exists() {
			zap.L().Debug("SNS message was an S3 Notification, initiating download")
			object := &sources.S3ObjectInfo{
				S3Bucket:    results[0].Str,
				S3ObjectKey: results[1].Str,
			}
			err := processS3Download(object, changes)
			if err != nil {
				return err
			}
		}

		// If both the prior cases failed, this must be an SNS Notification or invalid input
		switch gjson.Get(record.Body, "Type").Str {
		case "Notification": // SNS notification
			// This case is checking for CloudTrail logs directly wrapped in SNS Events
			zap.L().Debug("processing SNS notification")
			message := gjson.Get(record.Body, "Message").Str
			detail := gjson.Get(message, "detail")
			err := processCloudTrail(detail, changes)
			if err != nil {
				operation.LogError(errors.Wrap(err, "error processing SNS wrapped CloudTrail"))
			}
		case "SubscriptionConfirmation": // SNS confirmation message
			zap.L().Debug("processing SNS confirmation")
			topicArn, parseErr := arn.Parse(gjson.Get(record.Body, "TopicArn").Str)
			if err != nil {
				operation.LogWarn(errors.Wrap(parseErr, "invalid confirmation arn"))
				continue
			}
			token := gjson.Get(record.Body, "Token").Str
			if err = handleSnsConfirmation(topicArn, &token); err != nil {
				return err
			}
		default: // Unexpected type
			operation.LogWarn(errors.New("unexpected SNS message"),
				zap.String("type", gjson.Get(record.Body, "Type").Str),
				zap.String("body", record.Body))
		}
	}
	err = submitChanges(changes)
	return err
}

func processCloudTrail(cloudtrail gjson.Result, changes map[string]*resourceChange) error {
	if !cloudtrail.Exists() {
		return errors.WithStack(errors.New("dropping bad event"))
	}

	// One event could require multiple scans (e.g. a new VPC peering connection between two VPCs)
	for _, summary := range classifyCloudTrailLog(cloudtrail) {
		zap.L().Info("resource change required", zap.Any("changeDetail", summary))
		// Prevents the following from being de-duped mistakenly:
		//
		// Resources with the same ID in different regions (different regions)
		// Service scans in the same region (different resource types)
		// Resources with the same type in the same region (different resource IDs)
		key := summary.ResourceID + summary.ResourceType + summary.Region
		if entry, ok := changes[key]; !ok || summary.EventTime > entry.EventTime {
			changes[key] = summary // the newest event for this resource we've seen so far
		}
	}
	return nil
}

func processS3Download(object *sources.S3ObjectInfo, changes map[string]*resourceChange) error {
	logs, err := s3Svc.GetObject(&s3.GetObjectInput{
		Bucket: &object.S3Bucket,
		Key:    &object.S3ObjectKey,
	})
	if err != nil {
		return errors.Wrap(err, "error reading CloudTrail from S3")
	}

	reader, err := gzip.NewReader(bufio.NewReader(logs.Body))
	if err != nil {
		return errors.Wrap(err, "error creating gzip reader for S3 output")
	}

	stream := bufio.NewReader(reader)
	for {
		var line string
		line, err = stream.ReadString('\n')
		if err != nil {
			if err == io.EOF { // we are done
				err = nil
			}
			break
		}
		// Since we don't wont to lose an entire batch of logs to one bad message, we just log failures and continue
		err = processCloudTrail(gjson.Parse(line), changes)
		if err != nil {
			zap.L().Error("error processing CloudTrail from S3", zap.Error(errors.WithStack(err)))
		}
	}

	return err
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
		zap.L().Debug("deleting resources", zap.Any("deleteRequest", &deleteRequest))
		_, err := apiClient.Operations.DeleteResources(
			&operations.DeleteResourcesParams{Body: &deleteRequest, HTTPClient: httpClient})

		if err != nil {
			return errors.Wrapf(err, "resource deletion failed for: %#v", deleteRequest)
		}
	}

	if len(requestsByDelay) > 0 {
		batchInput := &sqs.SendMessageBatchInput{QueueUrl: &queueURL}
		// Send resource scan requests to the poller queue
		for delay, request := range requestsByDelay {
			zap.L().Debug("queueing resource scans", zap.Any("updateRequest", request))
			body, err := jsoniter.MarshalToString(request)
			if err != nil {
				return errors.Wrapf(err, "resource queueing failed: json marshal for: %#v", request)
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
