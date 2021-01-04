package s3sns

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
	"strings"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/cmd/opstools/s3list"
	"github.com/panther-labs/panther/internal/compliance/snapshotlogs"
	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/notify"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/awsretry"
)

const (
	maxRetries      = 7
	notifyChanDepth = 1000
)

type Input struct {
	Logger      *zap.SugaredLogger
	Session     *session.Session
	Account     string
	S3Path      string
	S3Region    string
	Topic       string
	Attributes  bool // if true, include SNS attributes which will cause the Rule Engine and Data Catalog Updater to receive
	Concurrency int
	Limit       uint64
	Stats       s3list.Stats // passed in so we can get stats if canceled
}

func S3SNS(ctx context.Context, input *Input) (err error) {
	clientsSession := input.Session.Copy(request.WithRetryer(aws.NewConfig().WithMaxRetries(maxRetries),
		awsretry.NewConnectionErrRetryer(maxRetries)))
	s3Client := s3.New(clientsSession.Copy(&aws.Config{Region: &input.S3Region}))
	snsClient := sns.New(clientsSession)
	lambdaClient := lambda.New(clientsSession)
	return s3sns(ctx, s3Client, snsClient, lambdaClient, input)
}

func s3sns(ctx context.Context, s3Client s3iface.S3API, snsClient snsiface.SNSAPI, lambdaClient lambdaiface.LambdaAPI,
	input *Input) (err error) {

	topicARN, err := getTopicArn(input.Topic, input.Account, *input.Session.Config.Region)
	if err != nil {
		return err
	}

	notifyChan := make(chan *events.S3Event, notifyChanDepth)

	// worker group
	workerGroup, workerCtx := errgroup.WithContext(ctx)
	for i := 0; i < input.Concurrency; i++ {
		workerGroup.Go(func() error {
			return publishNotifications(input.Logger, snsClient, lambdaClient, topicARN, input.Attributes, notifyChan)
		})
	}

	err = s3list.ListPath(workerCtx, &s3list.Input{
		Logger:   input.Logger,
		S3Client: s3Client,
		S3Path:   input.S3Path,
		Limit:    input.Limit,
		Write:    func(event *events.S3Event) { notifyChan <- event },
		Done:     func() { close(notifyChan) },
		Stats:    &input.Stats,
	})
	if err != nil { // ListPath() will call Done() function which will close notifyChan() on return causing workers to exit
		return err
	}

	return workerGroup.Wait() // returns any error from workers
}

func getTopicArn(topic, account, region string) (string, error) {
	endpoint, err := endpoints.DefaultResolver().EndpointFor("sns", region)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get endpoint information")
	}

	return arn.ARN{
		Partition: endpoint.PartitionID,
		Region:    region,
		AccountID: account,
		Service:   "sns",
		Resource:  topic,
	}.String(), nil
}

// post message per file as-if it was an S3 notification
func publishNotifications(logger *zap.SugaredLogger, snsClient snsiface.SNSAPI, lambdaClient lambdaiface.LambdaAPI,
	topicARN string, attributes bool, notifyChan chan *events.S3Event) (failed error) {

	for s3Event := range notifyChan {
		if failed != nil { // drain channel
			continue
		}

		bucket := s3Event.Records[0].S3.Bucket.Name
		key := s3Event.Records[0].S3.Object.Key
		size := s3Event.Records[0].S3.Object.Size

		logger.Debugf("sending s3://%s/%s (%d bytes) to SNS", bucket, key, size)

		s3Notification := notify.NewS3ObjectPutNotification(bucket, key, int(size))

		notifyJSON, err := jsoniter.MarshalToString(s3Notification)
		if err != nil {
			failed = errors.Wrapf(err, "failed to marshal %#v", s3Notification)
			continue
		}

		// Add SNS attributes based in type of data, this will enable
		// the rules engine and datacatalog updater to receive the notifications.
		// For back-filling a subscriber like Snowflake this should likely not be enabled.
		var messageAttributes map[string]*sns.MessageAttributeValue
		if attributes {
			dataType, err := awsglue.DataTypeFromS3Key(key)
			if err != nil {
				failed = errors.Wrapf(err, "failed to get data type from %s", key)
				continue
			}
			logType, err := logTypeFromS3Key(lambdaClient, key)
			if err != nil {
				failed = errors.Wrapf(err, "failed to get log type from %s", key)
				continue
			}
			messageAttributes = notify.NewLogAnalysisSNSMessageAttributes(dataType, logType)
		} else {
			messageAttributes = make(map[string]*sns.MessageAttributeValue)
		}

		publishInput := &sns.PublishInput{
			Message:           &notifyJSON,
			TopicArn:          &topicARN,
			MessageAttributes: messageAttributes,
		}

		_, err = snsClient.Publish(publishInput)
		if err != nil {
			failed = errors.Wrapf(err, "failed to publish %#v", *publishInput)
			continue
		}
	}

	return failed
}

// logType is not derivable from the s3 path, need to use API
var (
	initTablenameToLogType sync.Once
	tableNameToLogType     map[string]string
)

func logTypeFromS3Key(lambdaClient lambdaiface.LambdaAPI, s3key string) (logType string, err error) {
	keyParts := strings.Split(s3key, "/")
	if len(keyParts) < 2 {
		return "", errors.Errorf("logTypeFromS3Key failed parse on: %s", s3key)
	}

	initTablenameToLogType.Do(func() {
		logtypesAPI := &logtypesapi.LogTypesAPILambdaClient{
			LambdaName: logtypesapi.LambdaName,
			LambdaAPI:  lambdaClient,
		}
		var apiReply *logtypesapi.AvailableLogTypes
		apiReply, err = logtypesAPI.ListAvailableLogTypes(context.TODO())
		if err != nil {
			err = errors.Wrap(err, "failed to list logtypes")
			return
		}
		tableNameToLogType = make(map[string]string)
		// Append CloudSecurity log types to log types
		for _, logType := range append(apiReply.LogTypes, logtypes.CollectNames(snapshotlogs.LogTypes())...) {
			tableNameToLogType[pantherdb.TableName(logType)] = logType
		}
	})
	// catch any error from above
	if err != nil {
		return "", err
	}

	if logType, found := tableNameToLogType[keyParts[1]]; found {
		return logType, nil
	}
	return "", errors.Errorf("logTypeFromS3Key failed to find logType from: %s", s3key)
}
