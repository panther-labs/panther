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
	"os"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
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

func TestMain(m *testing.M) {
	// The failure tests will trigger backoff, make sure it doesn't take too long
	oldRetries := config.MaxRetries
	config.MaxRetries = 1
	exitVal := m.Run()
	config.MaxRetries = oldRetries

	os.Exit(exitVal)
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

func TestShouldConfirmSnsSubscriptionMessage(t *testing.T) {
	mockLambda := &testutils.LambdaMock{}
	config.LambdaClient = mockLambda
	mockFirehose := &testutils.FirehoseMock{}
	config.FirehoseClient = mockFirehose
	config.Env.StreamName = "testStreamName"
	resetCache()
	mockSns := &testutils.SnsMock{}
	getSnsClientFunc = func(region string) snsiface.SNSAPI {
		return mockSns
	}

	// nolint: lll
	snsConfirmationMsg := "{\"Type\" : \"SubscriptionConfirmation\",\n  \"MessageId\" : \"5d694afe-8598-422b-8a8b-578333d50df9\",\n  \"Token\" : \"2336412f37fb687f5d51e6e2425f004ae15784e4195f44c480796e9181756a3bf7e81188d3e842a98\",\n  \"TopicArn\" : \"arn:aws:sns:us-east-1:123456789012:testing-stuff\",\n  \"Message\" : \"You have chosen to subscribe to the topic arn:aws:sns:us-east-1:123456789012:testing-stuff.\\nTo confirm the subscription, visit the SubscribeURL included in this message.\",\n  \"SubscribeURL\" : \"https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription\u0026TopicArn=arn:aws:sns:us-east-1:012345678912:testing-stuff\u0026Token=213412412342134\",\n  \"Timestamp\" : \"2020-08-19T12:13:24.717Z\",\n  \"SignatureVersion\" : \"1\",\n  \"Signature\" : \"oEsP+\",\n  \"SigningCertURL\" : \"https://sns.us-east-1.amazonaws.com/SimpleNotificationService-a86cb10b4e1f29c941702d737128f7b6.pem\"\n}"
	sqsEvent := &events.SQSEvent{
		Records: []events.SQSMessage{
			{
				EventSourceARN: "arn:aws:sqs:eu-west-2:123456789012:test-queue-1",
				Body:           snsConfirmationMsg,
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

	expectedSnsConfirmation := &sns.ConfirmSubscriptionInput{
		TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:testing-stuff"),
		Token:    aws.String("2336412f37fb687f5d51e6e2425f004ae15784e4195f44c480796e9181756a3bf7e81188d3e842a98"),
	}
	mockSns.On("ConfirmSubscription", expectedSnsConfirmation).Return(&sns.ConfirmSubscriptionOutput{}, nil)

	require.NoError(t, Handle(context.TODO(), sqsEvent))

	mockLambda.AssertExpectations(t)
	mockFirehose.AssertExpectations(t)
	mockSns.AssertExpectations(t)
}

func resetCache() {
	sourcesCache = cache.New(getSourceInfo)
}
