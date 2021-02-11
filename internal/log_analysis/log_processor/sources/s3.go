package sources

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
	"context"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sns"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor/logstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/s3pipe"
	"github.com/panther-labs/panther/pkg/stringset"
)

const (
	DownloadMaxPartSize = 50 * 1024 * 1024                  // the max size of in memory buffers will be 3X as this due to multiple buffers
	DownloadMinPartSize = s3manager.DefaultDownloadPartSize // the min part size for efficiency

	s3TestEvent                 = "s3:TestEvent"
	cloudTrailValidationMessage = "CloudTrail validation message."
)

// ReadSnsMessage reads incoming messages containing SNS notifications and returns a slice of DataStream items
func ReadSnsMessage(ctx context.Context, message string) (result []*common.DataStream, err error) {
	snsNotificationMessage := &SnsNotification{}
	if err := jsoniter.UnmarshalFromString(message, snsNotificationMessage); err != nil {
		return nil, err
	}

	switch snsNotificationMessage.Type {
	case "Notification":
		streams, err := handleNotificationMessage(ctx, snsNotificationMessage)
		if err != nil {
			return nil, err
		}
		result = append(result, streams...)
	case "SubscriptionConfirmation":
		err := ConfirmSubscription(snsNotificationMessage)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("received unexpected message in SQS queue")
	}
	return result, nil
}

// ConfirmSubscription will confirm the SNS->SQS subscription
func ConfirmSubscription(notification *SnsNotification) (err error) {
	operation := common.OpLogManager.Start("ConfirmSubscription", common.OpLogSNSServiceDim)
	defer func() {
		operation.Stop()
		// sns dim info
		operation.Log(err, zap.String("topicArn", notification.TopicArn))
	}()

	topicArn, err := arn.Parse(notification.TopicArn)
	if err != nil {
		return errors.Wrap(err, "failed to parse topic arn: "+notification.TopicArn)
	}
	snsClient := sns.New(common.Session, aws.NewConfig().WithRegion(topicArn.Region))
	subscriptionConfiguration := &sns.ConfirmSubscriptionInput{
		Token:    notification.Token,
		TopicArn: aws.String(notification.TopicArn),
	}
	_, err = snsClient.ConfirmSubscription(subscriptionConfiguration)
	if err != nil {
		err = errors.Wrap(err, "failed to confirm subscription for: "+notification.TopicArn)
		return err
	}
	return nil
}

func handleNotificationMessage(ctx context.Context, notification *SnsNotification) (result []*common.DataStream, err error) {
	s3Objects, err := ParseNotification(notification.Message)
	if err != nil {
		return nil, err
	}
	for _, s3Object := range s3Objects {
		if shouldIgnoreS3Object(s3Object) {
			continue
		}
		var dataStream *common.DataStream
		dataStream, err = buildStream(ctx, s3Object)
		if err != nil {
			return
		}
		if dataStream != nil {
			result = append(result, dataStream)
		}
	}
	return result, err
}

func shouldIgnoreS3Object(s3Object *S3ObjectInfo) bool {
	// We should ignore S3 objects that end in `/`.
	// These objects are used in S3 to define a "folder" and do not contain data.
	// We also ignore empty files since they do not contain any logs, they log errors that page on-call, and some
	// systems like to create them during their normal process of delivering logs to Panther.
	return s3Object.S3ObjectSize == 0 || strings.HasSuffix(s3Object.S3ObjectKey, "/")
}

func buildStream(ctx context.Context, s3Object *S3ObjectInfo) (*common.DataStream, error) {
	key, bucket := s3Object.S3ObjectKey, s3Object.S3Bucket
	s3Client, src, err := getS3Client(bucket, key)
	if err != nil {
		err = errors.Wrapf(err, "failed to get S3 client for s3://%s/%s", bucket, key)
		return nil, err
	}
	if src == nil {
		zap.L().Warn("no source configured for S3 object",
			zap.String("bucket", bucket),
			zap.String("key", key))
		return nil, nil
	}

	downloader := s3pipe.Downloader{
		S3:       s3Client,
		PartSize: calculatePartSize(s3Object.S3ObjectSize),
	}
	// gzip streams are transparently uncompressed
	r := downloader.Download(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	var stream logstream.Stream
	switch src.IntegrationType {
	case models.IntegrationTypeAWS3:
		if isCloudTrailLog(key) && stringset.Contains(src.RequiredLogTypes(), "AWS.CloudTrail") {
			zap.L().Debug("detected CloudTrail logs", zap.String("bucket", bucket), zap.String("key", key))
			stream = logstream.NewJSONArrayStream(r, DownloadMinPartSize, "Records")
		} else {
			stream = logstream.NewLineStream(r, DownloadMinPartSize)
		}
	default:
		// Set the buffer size to something big to avoid multiple fill() calls if possible
		stream = logstream.NewLineStream(r, DownloadMinPartSize)
	}

	return &common.DataStream{
		Stream:       stream,
		Closer:       r,
		Source:       src,
		S3Bucket:     s3Object.S3Bucket,
		S3ObjectKey:  s3Object.S3ObjectKey,
		S3ObjectSize: s3Object.S3ObjectSize,
	}, nil
}

func calculatePartSize(size int64) int64 {
	// we want this as large as possible to minimize S3 api calls, not more than DownloadMaxPartSize to control memory use
	partSize := size / 2 // use 1/2 to allow processing first half while reading second half on small files
	if partSize > DownloadMaxPartSize {
		return DownloadMaxPartSize
	}
	if partSize < DownloadMinPartSize { // min part size for efficiency
		return DownloadMinPartSize
	}
	return partSize
}

// ParseNotification parses a message received
func ParseNotification(message string) ([]*S3ObjectInfo, error) {
	s3Objects := parseCloudTrailNotification(message)

	// If the input was not a CloudTrail notification, s3Objects will be nil
	if s3Objects != nil {
		return s3Objects, nil
	}

	s3Objects = parseS3Event(message)
	if s3Objects != nil {
		return s3Objects, nil
	}

	if isTestS3Event(message) || isCloudTrailValidationMessage(message) {
		//In this case return an empty array. There are no S3 objects to process
		return []*S3ObjectInfo{}, nil
	}

	return nil, errors.New("notification is not of known type: " + message)
}

// The function will try to parse input as if it was a CloudTrail notification
// If the message is not a CloudTrail notification, it returns nil
func parseCloudTrailNotification(message string) (result []*S3ObjectInfo) {
	cloudTrailNotification := &cloudTrailNotification{}
	err := jsoniter.UnmarshalFromString(message, cloudTrailNotification)
	if err != nil {
		return nil
	}

	if len(cloudTrailNotification.S3ObjectKey) == 0 {
		return nil
	}

	for _, s3Key := range cloudTrailNotification.S3ObjectKey {
		info := &S3ObjectInfo{
			S3Bucket:    *cloudTrailNotification.S3Bucket,
			S3ObjectKey: *s3Key,
		}
		result = append(result, info)
	}
	return result
}

// parseS3Event will try to parse input as if it was an S3 Event (https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html)
// If the input was not an S3 Event  notification it will return nil
func parseS3Event(message string) (result []*S3ObjectInfo) {
	notification := &events.S3Event{}
	err := jsoniter.UnmarshalFromString(message, notification)
	if err != nil {
		return nil
	}

	if len(notification.Records) == 0 {
		return nil
	}
	for _, record := range notification.Records {
		urlDecodedKey, err := url.PathUnescape(record.S3.Object.Key)
		if err != nil {
			return nil
		}
		info := &S3ObjectInfo{
			S3Bucket:     record.S3.Bucket.Name,
			S3ObjectKey:  urlDecodedKey,
			S3ObjectSize: record.S3.Object.Size,
		}
		result = append(result, info)
	}
	return result
}

// The method returns true if the received event is an S3 Test event
func isTestS3Event(message string) bool {
	notification := &events.S3TestEvent{}
	err := jsoniter.UnmarshalFromString(message, notification)
	if err != nil {
		return false
	}
	return notification.Event == s3TestEvent
}

// The method returns true if the received event is a CloudTrail validation message
func isCloudTrailValidationMessage(message string) bool {
	return message == cloudTrailValidationMessage
}

// cloudTrailNotification is the notification sent by CloudTrail whenever it delivers a new log file to S3
type cloudTrailNotification struct {
	S3Bucket    *string   `json:"s3Bucket"`
	S3ObjectKey []*string `json:"s3ObjectKey"`
}

// S3ObjectInfo contains information about the S3 object
type S3ObjectInfo struct {
	S3Bucket     string
	S3ObjectKey  string
	S3ObjectSize int64
}

// SnsNotification struct represents an SNS message arriving to Panther SQS from a customer account.
// The message can either be of type 'Notification' or 'SubscriptionConfirmation'
// Since there is no AWS SDK-provided struct to represent both types
// we had to create this custom type to include fields from both types.
type SnsNotification struct {
	events.SNSEntity
	Token *string `json:"Token"`
}

// nolint:lll
// Match `AccountID_CloudTrail_RegionName_YYYYMMDDTHHmmZ_UniqueString.FileNameFormat` format
// https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html
var rxCloudTrailLog = regexp.MustCompile(`^(?P<account>\d{12})_CloudTrail_(?P<region>[^_]+)_(?P<ts>\d{8}T\d{4}Z)_\w+.json.gz$`)

func isCloudTrailLog(key string) bool {
	return rxCloudTrailLog.MatchString(path.Base(key))
}
