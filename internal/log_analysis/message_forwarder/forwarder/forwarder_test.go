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
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/cache"
	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/config"
	"github.com/panther-labs/panther/pkg/testutils"
)

var availableSqsSources = []*models.SourceIntegration{
	{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			IntegrationID:   "45c378a7-2e36-4b12-8e16-2d3c49ff1371",
			IntegrationType: models.IntegrationTypeSqs,
			SqsConfig: &models.SqsConfig{
				QueueURL: "https://sqs.eu-west-2.amazonaws.com/123456789012/test-queue-1",
			},
		},
	},
	{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			IntegrationID:   "45c378a7-2e36-4b12-8e16-2d3c49ff1372",
			IntegrationType: models.IntegrationTypeSqs,
			SqsConfig: &models.SqsConfig{
				QueueURL: "https://sqs.eu-west-2.amazonaws.com/123456789012/test-queue-2",
			},
		},
	},
}

func TestShouldSendBatchRequest(t *testing.T) {
	mockLambda := &testutils.LambdaMock{}
	config.LambdaClient = mockLambda
	mockFirehose := &testutils.FirehoseMock{}
	config.FirehoseClient = mockFirehose
	config.Env.StreamName = "testStreamName"
	resetCache()

	sqsEvent := &events.SQSEvent{
		Records: []events.SQSMessage{
			{
				EventSourceARN: "arn:aws:sqs:eu-west-2:123456789012:test-queue-1",
				Body:           "payload1",
			},
			{
				EventSourceARN: "arn:aws:sqs:eu-west-2:123456789012:test-queue-2",
				Body:           "payload2",
			},
		},
	}

	marshaledSources, err := jsoniter.Marshal(availableSqsSources)
	require.NoError(t, err)

	mockLambda.On("Invoke", mock.Anything).Return(
		&lambda.InvokeOutput{
			Payload:    marshaledSources,
			StatusCode: aws.Int64(http.StatusOK),
		}, nil)

	expectedForwarderMessages := []Message{
		{
			Payload:             "payload1",
			SourceIntegrationID: "45c378a7-2e36-4b12-8e16-2d3c49ff1371",
		},
		{
			Payload:             "payload2",
			SourceIntegrationID: "45c378a7-2e36-4b12-8e16-2d3c49ff1372",
		},
	}
	var expectedFirehoseRecords []*firehose.Record
	for _, message := range expectedForwarderMessages {
		serializedMsg, err := jsoniter.MarshalToString(message)
		require.NoError(t, err)
		expectedFirehoseRecords = append(expectedFirehoseRecords, &firehose.Record{
			Data: []byte(serializedMsg + "\n"),
		})
	}

	expectedFirehoseInput := &firehose.PutRecordBatchInput{
		Records:            expectedFirehoseRecords,
		DeliveryStreamName: aws.String("testStreamName"),
	}
	mockFirehose.On("PutRecordBatchWithContext", mock.Anything, expectedFirehoseInput, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, nil)

	require.NoError(t, Handle(context.TODO(), sqsEvent))

	mockLambda.AssertExpectations(t)
	mockFirehose.AssertExpectations(t)
}

func TestShouldSkipMessagesNotRelatedToSource(t *testing.T) {
	mockLambda := &testutils.LambdaMock{}
	config.LambdaClient = mockLambda
	mockFirehose := &testutils.FirehoseMock{}
	config.FirehoseClient = mockFirehose
	config.Env.StreamName = "testStreamName"
	resetCache()

	sqsEvent := &events.SQSEvent{
		Records: []events.SQSMessage{
			{
				EventSourceARN: "arn:aws:sqs:eu-west-2:123456789012:test-queue-1",
				Body:           "payload1",
			},
			// This message is coming from an unregistered queue and should be ignored
			{
				EventSourceARN: "arn:aws:sqs:eu-west-2:123456789012:unregistered-queue",
				Body:           "payload2",
			},
		},
	}

	marshaledSources, err := jsoniter.Marshal(availableSqsSources)
	require.NoError(t, err)

	mockLambda.On("Invoke", mock.Anything).Return(
		&lambda.InvokeOutput{
			Payload:    marshaledSources,
			StatusCode: aws.Int64(http.StatusOK),
		}, nil)

	expectedForwarderMessage := Message{
		Payload:             "payload1",
		SourceIntegrationID: "45c378a7-2e36-4b12-8e16-2d3c49ff1371",
	}

	serializedMsg, err := jsoniter.MarshalToString(expectedForwarderMessage)
	require.NoError(t, err)
	expectedFirehoseRecord := &firehose.Record{
		Data: []byte(serializedMsg + "\n"),
	}

	expectedFirehoseInput := &firehose.PutRecordBatchInput{
		Records:            []*firehose.Record{expectedFirehoseRecord},
		DeliveryStreamName: aws.String("testStreamName"),
	}

	mockFirehose.On("PutRecordBatchWithContext", mock.Anything, expectedFirehoseInput, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, nil)

	require.NoError(t, Handle(context.TODO(), sqsEvent))

	mockLambda.AssertExpectations(t)
	mockFirehose.AssertExpectations(t)
}

func TestShouldFailIfPartialFailureToPutRecord(t *testing.T) {
	mockLambda := &testutils.LambdaMock{}
	config.LambdaClient = mockLambda
	mockFirehose := &testutils.FirehoseMock{}
	config.FirehoseClient = mockFirehose
	resetCache()

	sqsEvent := &events.SQSEvent{
		Records: []events.SQSMessage{
			{
				EventSourceARN: "arn:aws:sqs:eu-west-2:123456789012:test-queue-1",
				Body:           "payload1",
			},
		},
	}

	marshaledSources, err := jsoniter.Marshal(availableSqsSources)
	require.NoError(t, err)

	mockLambda.On("Invoke", mock.Anything).Return(
		&lambda.InvokeOutput{
			Payload:    marshaledSources,
			StatusCode: aws.Int64(http.StatusOK),
		}, nil)

	mockFirehose.On("PutRecordBatchWithContext", mock.Anything, mock.Anything, mock.Anything).Return(
		&firehose.PutRecordBatchOutput{FailedPutCount: aws.Int64(1)}, nil)

	require.Error(t, Handle(context.TODO(), sqsEvent))

	mockLambda.AssertExpectations(t)
	mockFirehose.AssertExpectations(t)
}

func TestShouldFailIfFailureToPutRecord(t *testing.T) {
	mockLambda := &testutils.LambdaMock{}
	config.LambdaClient = mockLambda
	mockFirehose := &testutils.FirehoseMock{}
	config.FirehoseClient = mockFirehose
	resetCache()

	sqsEvent := &events.SQSEvent{
		Records: []events.SQSMessage{
			{
				EventSourceARN: "arn:aws:sqs:eu-west-2:123456789012:test-queue-1",
				Body:           "payload1",
			},
		},
	}

	marshaledSources, err := jsoniter.Marshal(availableSqsSources)
	require.NoError(t, err)

	mockLambda.On("Invoke", mock.Anything).Return(
		&lambda.InvokeOutput{
			Payload:    marshaledSources,
			StatusCode: aws.Int64(http.StatusOK),
		}, nil)

	mockFirehose.On("PutRecordBatchWithContext", mock.Anything, mock.Anything, mock.Anything).Return(
		&firehose.PutRecordBatchOutput{}, errors.New("error"))

	require.Error(t, Handle(context.TODO(), sqsEvent))

	mockLambda.AssertExpectations(t)
	mockFirehose.AssertExpectations(t)
}

func resetCache() {
	sourcesCache = cache.New(getSourceInfo)
}
