package processor

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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
	"time"

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

	api "github.com/panther-labs/panther/api/lambda/resources/models"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/internal/log_analysis/notify"
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
	changes := make(map[string]*resourceChange, len(batch.Records))

	// Get the most recent integrations to map Account ID to IntegrationID
	if err = refreshAccounts(); err != nil {
		return err
	}

	// Using gjson to get only the fields we need is > 10x faster than running json.Unmarshal multiple times
	//
	// Since we don't want one bad notification to lose us the rest, we log failures and continue.
	for _, record := range batch.Records {
		// Check for a notification from the log processor that there are newly processed CloudTrail logs
		if id, found := record.MessageAttributes["id"]; found {
			if id.StringValue != nil && *id.StringValue == "AWS.CloudTrail" {
				if isLogProcessorCloudTrail, err := handleLogProcessorCloudTrail(record.Body, changes); err != nil {
					return err
				} else if isLogProcessorCloudTrail {
					continue
				}
			}
		}

		// Check for SNS raw message delivery of CloudTrail
		detail := gjson.Get(record.Body, "detail")
		if detail.Exists() {
			zap.L().Debug("processing raw CloudTrail")
			err := handleCloudTrail(detail, changes)
			if err != nil {
				zap.L().Error("error processing raw CloudTrail", zap.Error(err))
			}
			continue
		}

		// If both the prior cases failed, this must be an SNS Notification or invalid input
		switch gjson.Get(record.Body, "Type").Str {
		case "Notification":
			// Check for CloudTrail logs wrapped in SNS Events
			zap.L().Debug("processing SNS notification")
			message := gjson.Get(record.Body, "Message").Str
			detail := gjson.Get(message, "detail")
			if !detail.Exists() {
				zap.L().Error("error extracting detail from SNS wrapped CloudTrail")
				continue
			}
			err := handleCloudTrail(detail, changes)
			if err != nil {
				operation.LogError(errors.Wrap(err, "error processing SNS wrapped CloudTrail"))
			}
			continue

		case "SubscriptionConfirmation":
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

func handleLogProcessorCloudTrail(messageBody string, changes map[string]*resourceChange) (ok bool, err error) {
	notification := &notify.S3Notification{}
	if err := jsoniter.UnmarshalFromString(messageBody, notification); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal record")
	}

	// anything?
	if len(notification.Records) == 0 {
		return false, nil
	}

	// process events and return true
	for _, eventRecord := range notification.Records {
		object := &sources.S3ObjectInfo{
			S3Bucket:    eventRecord.S3.Bucket.Name,
			S3ObjectKey: eventRecord.S3.Object.Key,
		}
		err := handleS3Download(object, changes)
		if err != nil {
			return false, err
		}
	}
	return true, err
}

// handleCloudTrail takes a single CloudTrail log line and determines what scans if any need to be made as a result
// of the log.
func handleCloudTrail(cloudtrail gjson.Result, changes map[string]*resourceChange) error {
	metadata, err := preprocessCloudTrailLog(cloudtrail)
	if err != nil {
		return err
	}
	if metadata == nil {
		return nil
	}
	cweAccounts[generateSourceKey(metadata)] = time.Now()

	return processCloudTrailLog(cloudtrail, metadata, changes)
}

// handleS3Download processes an s3 Notification from the log analysis pipeline by downloading
// the already processed CloudTrail logs and sending them to the CloudTrail classifier.
//
// Because this data has already been pre-processed, we assume it is in the correct format and return all errors.
func handleS3Download(object *sources.S3ObjectInfo, changes map[string]*resourceChange) error {
	logs, err := s3Client.GetObject(&s3.GetObjectInput{
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
	for err == nil {
		// First download the next line of CloudTrail logs
		var line string
		line, err = stream.ReadString('\n')
		if err != nil {
			if err == io.EOF { // we are done
				err = nil
			} else {
				err = errors.Wrap(err, "unexpected error reading line from s3")
			}
			break
		}

		// Parse the line and determine if we should continue
		detail := gjson.Parse(line)
		var metadata *CloudTrailMetadata
		metadata, err = preprocessCloudTrailLog(detail)
		if err != nil {
			return err
		}
		if metadata == nil {
			continue
		}
		if checkCWECache(generateSourceKey(metadata)) {
			// If we're currently seeing CloudTrail via CWE, we don't process the duplicate data in S3
			zap.L().Debug(
				"skipping s3 notification in favor of CloudTrail via CWE",
				zap.String("region", metadata.region),
				zap.String("accountID", metadata.accountID),
			)
			continue
		}

		// Process the line
		err = processCloudTrailLog(detail, metadata, changes)
	}

	return err
}

// generateSourceKey creates the key used for the cweAccounts cache for a given CloudTrail metadata struct
func generateSourceKey(metadata *CloudTrailMetadata) string {
	return metadata.accountID + "/" + metadata.region
}

func submitChanges(changes map[string]*resourceChange) error {
	var deleteRequest api.DeleteResourcesInput
	requestsByDelay := make(map[int64]*poller.ScanMsg)

	for _, change := range changes {
		if change.Delete {
			deleteRequest.Resources = append(deleteRequest.Resources, api.DeleteEntry{
				ID: change.ResourceID,
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
				AWSAccountID:            &change.AwsAccountID,
				IntegrationID:           &change.IntegrationID,
				Region:                  region,
				ResourceID:              resourceID,
				ResourceType:            &change.ResourceType,
				Enabled:                 accounts[change.AwsAccountID].Enabled,
				RegionIgnoreList:        accounts[change.AwsAccountID].RegionIgnoreList,
				ResourceTypeIgnoreList:  accounts[change.AwsAccountID].ResourceTypeIgnoreList,
				ResourceRegexIgnoreList: accounts[change.AwsAccountID].ResourceRegexIgnoreList,
			})
		}
	}

	// Send deletes to resources-api
	if len(deleteRequest.Resources) > 0 {
		zap.L().Debug("deleting resources", zap.Any("deleteRequest", &deleteRequest))
		input := api.LambdaInput{DeleteResources: &deleteRequest}
		if _, err := resourcesClient.Invoke(&input, nil); err != nil {
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

		if _, err := sqsbatch.SendMessageBatch(sqsClient, maxBackoffSeconds, batchInput); err != nil {
			return err
		}
	}

	return nil
}
