package forwarder

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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	sourcemodels "github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/cache"
	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/config"
	"github.com/panther-labs/panther/pkg/awsbatch/firehosebatch"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type Message struct {
	Payload             string `json:"payload" validate:"required,min=1"`
	SourceIntegrationID string `json:"sourceId" validate:"required,uuid4"`
}

const RecordDelimiter = '\n'

var (
	sourcesCache     = cache.New(getSourceInfo)
	getSnsClientFunc = getSnsClient
)

func Handle(ctx context.Context, event *events.SQSEvent) error {
	var firehoseRecords []*firehose.Record
	for _, record := range event.Records {
		queueName := getQueueNameFromArn(record.EventSourceARN)
		zap.L().Debug("Found queue name", zap.String("queueName", queueName))
		cacheValue, ok := sourcesCache.Get(queueName)
		// Integration ID not present, skipping
		if !ok {
			zap.L().Warn("didn't find integrationId for message, skipping")
			continue
		}
		integrationID := cacheValue.(string)
		zap.L().Debug("Found integration", zap.String("integrationId", integrationID))
		isSubscriptionMsg, err := confirmIfSnsSubscriptionMessage(record.Body)
		if isSubscriptionMsg {
			if err != nil {
				// best effort - just log warning
				zap.L().Warn("failed to confirm subscription", zap.Error(err))
			}
			continue
		}

		message := Message{
			Payload:             record.Body,
			SourceIntegrationID: integrationID,
		}
		data, err := jsoniter.Marshal(message)
		if err != nil {
			return errors.Wrap(err, "failed to marshal event")
		}
		// Adding new line
		data = append(data, RecordDelimiter)
		firehoseRecords = append(firehoseRecords, &firehose.Record{Data: data})
	}

	zap.L().Debug("Sending data", zap.Int("size", len(firehoseRecords)))

	if len(firehoseRecords) == 0 {
		zap.L().Debug("No records to process")
		return nil
	}
	// Maximum Kinesis Firehose batch put request is 4MB, maximum SQS queue message size is 256KB
	// Since each Lambda invocation pulls up to 10 messages, each PutRecordBatch request cannot reach the 4MB limit.
	request := firehose.PutRecordBatchInput{
		Records:            firehoseRecords,
		DeliveryStreamName: &config.Env.StreamName,
	}
	return firehosebatch.Send(ctx, config.FirehoseClient, request, config.MaxRetries)
}

func getSourceInfo() (map[string]interface{}, error) {
	input := &sourcemodels.LambdaInput{ListIntegrations: &sourcemodels.ListIntegrationsInput{
		IntegrationType: aws.String(sourcemodels.IntegrationTypeSqs),
	}}
	var output []*sourcemodels.SourceIntegration
	err := genericapi.Invoke(config.LambdaClient, config.SourceAPIFunctionName, input, &output)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch available integrations")
	}
	result := make(map[string]interface{}, len(output))
	for _, source := range output {
		result[getQueueNameFromURL(source.SqsConfig.QueueURL)] = source.IntegrationID
	}
	return result, nil
}

func getQueueNameFromArn(queueArn string) string {
	parseArn, err := arn.Parse(queueArn)
	if err != nil {
		panic("failed to parse Queue arn")
	}
	return parseArn.Resource
}

func getQueueNameFromURL(queueURL string) string {
	urlParts := strings.Split(queueURL, "/")
	if len(urlParts) == 0 {
		panic("failed to parse queue URL")
	}
	return urlParts[len(urlParts)-1]
}

// Tries to identify if message is an SNS topic subscription message
func confirmIfSnsSubscriptionMessage(message string) (bool, error) {
	msgType := gjson.Get(message, "Type")
	if !msgType.Exists() {
		return false, nil
	}
	if msgType.String() != "SubscriptionConfirmation" {
		return false, nil
	}
	topicArn := gjson.Get(message, "TopicArn")
	if !topicArn.Exists() {
		return false, nil
	}
	token := gjson.Get(message, "Token")
	if !token.Exists() {
		return false, nil
	}
	parsedTopicArn, err := arn.Parse(topicArn.String())
	if err != nil {
		return false, nil
	}

	snsClient := getSnsClientFunc(parsedTopicArn.Region)
	subscriptionConfiguration := &sns.ConfirmSubscriptionInput{
		Token:    aws.String(token.String()),
		TopicArn: aws.String(topicArn.String()),
	}
	_, err = snsClient.ConfirmSubscription(subscriptionConfiguration)
	if err != nil {
		return true, errors.Wrapf(err, "failed to confirm subscription for: %s", topicArn.String())
	}
	return true, nil
}

func getSnsClient(region string) snsiface.SNSAPI {
	return sns.New(config.AwsSession, aws.NewConfig().WithRegion(region))
}
