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
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
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

	"github.com/panther-labs/panther/cmd/opstools/s3list"
	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/notify"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

const (
	topicArnTemplate = "arn:aws:sns:%s:%s:%s"
)

func S3Topic(sess *session.Session, account, s3path, s3region, topic string, attributes bool,
	concurrency int, limit uint64, stats *s3list.Stats) (err error) {

	return s3sns(s3.New(sess.Copy(&aws.Config{Region: &s3region})), sns.New(sess), lambda.New(sess),
		account, s3path, topic, *sess.Config.Region, attributes, concurrency, limit, stats)
}

func s3sns(s3Client s3iface.S3API, snsClient snsiface.SNSAPI, lambdaClient lambdaiface.LambdaAPI,
	account, s3path, topic, topicRegion string, attributes bool,
	concurrency int, limit uint64, stats *s3list.Stats) (failed error) {

	topicARN := fmt.Sprintf(topicArnTemplate, topicRegion, account, topic)

	errChan := make(chan error)
	notifyChan := make(chan *events.S3Event, 1000)

	var queueWg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		queueWg.Add(1)
		go func() {
			publishNotifications(snsClient, lambdaClient, topicARN, attributes, notifyChan, errChan)
			queueWg.Done()
		}()
	}

	queueWg.Add(1)
	go func() {
		s3list.ListPath(s3Client, s3path, limit, notifyChan, errChan, stats)
		queueWg.Done()
	}()

	var errorWg sync.WaitGroup
	errorWg.Add(1)
	go func() {
		for err := range errChan { // return last error
			failed = err
		}
		errorWg.Done()
	}()

	queueWg.Wait()
	close(errChan)
	errorWg.Wait()

	return failed
}

// post message per file as-if it was an S3 notification
func publishNotifications(snsClient snsiface.SNSAPI, lambdaClient lambdaiface.LambdaAPI,
	topicARN string, attributes bool,
	notifyChan chan *events.S3Event, errChan chan error) {

	var failed bool
	for s3Event := range notifyChan {
		if failed { // drain channel
			continue
		}

		bucket := s3Event.Records[0].S3.Bucket.Name
		key := s3Event.Records[0].S3.Object.Key
		size := s3Event.Records[0].S3.Object.Size

		zap.L().Debug("sending file to SNS",
			zap.String("bucket", bucket),
			zap.String("key", key),
			zap.Int64("size", size))

		s3Notification := notify.NewS3ObjectPutNotification(bucket, key, int(size))

		notifyJSON, err := jsoniter.MarshalToString(s3Notification)
		if err != nil {
			errChan <- errors.Wrapf(err, "failed to marshal %#v", s3Notification)
			failed = true
			continue
		}

		// Add SNS attributes based in type of data, this will enable
		// the rules engine and datacatalog updater to receive the notifications.
		// For back-filling a subscriber like Snowflake this should likely not be enabled.
		var messageAttributes map[string]*sns.MessageAttributeValue
		if attributes {
			dataType, err := awsglue.DataTypeFromS3Key(key)
			if err != nil {
				errChan <- errors.Wrapf(err, "failed to get data type from %s", key)
				failed = true
				continue
			}
			logType, err := logTypeFromS3Key(lambdaClient, key)
			if err != nil {
				errChan <- errors.Wrapf(err, "failed to get log type from %s", key)
				failed = true
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
			errChan <- errors.Wrapf(err, "failed to publish %#v", *publishInput)
			failed = true
			continue
		}
	}
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
		const lambdaName, method = "panther-logtypes-api", "listAvailableLogTypes"
		var resp *lambda.InvokeOutput
		resp, err = lambdaClient.Invoke(&lambda.InvokeInput{
			FunctionName: aws.String(lambdaName),
			Payload:      []byte(fmt.Sprintf(`{ "%s": {}}`, method)),
		})
		if err != nil {
			err = errors.Wrapf(err, "failed to invoke %#v", method)
			return
		}
		if resp.FunctionError != nil {
			err = errors.Errorf("%s: failed to invoke %#v", *resp.FunctionError, method)
			return
		}

		var availableLogTypes logtypesapi.AvailableLogTypes
		err = jsoniter.Unmarshal(resp.Payload, &availableLogTypes)
		if err != nil {
			err = errors.Wrapf(err, "failed to unmarshal: %s", string(resp.Payload))
			return
		}

		tableNameToLogType = make(map[string]string)
		for _, logType := range availableLogTypes.LogTypes {
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
