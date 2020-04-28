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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
)

const (
	defaultTestTimeLimit = time.Second * 2
)

var (
	streamTestDeadline time.Time

	streamTestSqsClient *mockSQS

	snsMessage = `{}` // empty JSON is fine

	streamTestLambdaEvent = events.SQSEvent{
		Records: []events.SQSMessage{
			{
				Body: snsMessage,
			},
		},
	}

	streamTestReceiveMessageOutput = &sqs.ReceiveMessageOutput{
		Messages: []*sqs.Message{
			{
				Body:          aws.String(snsMessage),
				ReceiptHandle: aws.String("testMessageHandle"),
			},
		},
	}

	streamTestMessagesAboveThreshold = &sqs.GetQueueAttributesOutput{
		Attributes: map[string]*string{
			sqs.QueueAttributeNameApproximateNumberOfMessages: aws.String("200"),
		},
	}
	streamTestMessagesBelowThreshold = &sqs.GetQueueAttributesOutput{
		Attributes: map[string]*string{
			sqs.QueueAttributeNameApproximateNumberOfMessages: aws.String("0"),
		},
	}
)

func TestStreamEventsLambdaPlusSQS(t *testing.T) {
	// lambda events and sqs events
	initTest()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()
	// this one is below threshold, which breaks the loop
	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesBelowThreshold, nil).Once()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestDeadline, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records)+len(streamTestReceiveMessageOutput.Messages), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsOnlyLambda(t *testing.T) {
	// only lambda events
	initTest()

	// this one has no messages, which breaks the loop
	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesBelowThreshold, nil).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestDeadline, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsProcessingTimeLimitExceeded(t *testing.T) {
	initTest()

	// should only process the lambda events although there are sqs events in the q cuz of timeout
	deadline := streamTestDeadline.Add(-defaultTestTimeLimit) // polling loop should not be entered

	sqsMessageCount, err := streamEvents(streamTestSqsClient, deadline, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsReadEventError(t *testing.T) {
	initTest()

	_, err := streamEvents(streamTestSqsClient, streamTestDeadline, streamTestLambdaEvent,
		noopProcessorFunc, failReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "readEventError", err.Error())
}

func TestStreamEventsProcessError(t *testing.T) {
	initTest()

	// ensure sqs reading go routine exits quickly to avoid data races between tests
	deadline := streamTestDeadline.Add(-defaultTestTimeLimit) // polling loop should not be entered

	_, err := streamEvents(streamTestSqsClient, deadline, streamTestLambdaEvent,
		failProcessorFunc, noopReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error())
}

func TestStreamEventsProcessErrorAndReadEventError(t *testing.T) {
	initTest()

	_, err := streamEvents(streamTestSqsClient, streamTestDeadline, streamTestLambdaEvent,
		failProcessorFunc, failReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error()) // expect the processError NOT readEventError
}

func TestStreamEventsReceiveSQSError(t *testing.T) {
	initTest()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	// this one fails
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{},
		fmt.Errorf("receiveError")).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestDeadline, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	assert.Error(t, err)
	assert.Equal(t, 0, sqsMessageCount)
	assert.Equal(t, "failure receiving messages from https://fakesqsurl: receiveError", err.Error())
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsDeleteSQSError(t *testing.T) {
	initTest()

	logs := mockLogger()

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()
	// this one is below threshold, which breaks the loop
	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesBelowThreshold, nil).Once()
	// this one fails
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{
		Failed:     []*sqs.BatchResultErrorEntry{{}},
		Successful: []*sqs.DeleteMessageBatchResultEntry{},
	}, fmt.Errorf("deleteError")).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestDeadline, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)

	// keep sure we get error logging
	actualLogs := logs.AllUntimed()
	expectedLogs := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{
				Level:   zapcore.ErrorLevel,
				Message: "failure deleting sqs messages",
			},
			Context: []zapcore.Field{
				zap.String("guidance", "failed messages will be reprocessed"),
				zap.String("queueURL", common.Config.SqsQueueURL),
				zap.Int("numberOfFailedMessages", 1),
				zap.Int("numberOfSuccessfulMessages", 0),
				zap.Error(errors.New("deleteError")),
			},
		},
	}

	assert.NoError(t, err) // this does not cause failure of the lambda
	assert.Equal(t, len(streamTestLambdaEvent.Records)+len(streamTestReceiveMessageOutput.Messages), sqsMessageCount)
	assert.Equal(t, len(expectedLogs), len(actualLogs))
	for i := range expectedLogs {
		assertLogEqual(t, expectedLogs[i], actualLogs[i])
	}
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsSQSOverLimitError(t *testing.T) {
	// lambda events and sqs events
	initTest()

	// on an over limit error, just stop processing (deletes messages processed from sqs queue)

	streamTestSqsClient.On("GetQueueAttributes", mock.Anything).Return(streamTestMessagesAboveThreshold, nil).Once()
	// this one has overlimit error , which breaks the loop
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{},
		awserr.New(sqs.ErrCodeOverLimit, "", fmt.Errorf(sqs.ErrCodeOverLimit))).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestDeadline, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamSQSBatchDelete(t *testing.T) {
	// 1 event, 1 batch
	initTest()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()
	deleteSqsMessages(streamTestSqsClient, [][]*string{
		make([]*string, 1),
	})
	streamTestSqsClient.AssertExpectations(t)

	// 5 events, 1 batch
	initTest()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()
	deleteSqsMessages(streamTestSqsClient, [][]*string{
		make([]*string, 5),
	})
	streamTestSqsClient.AssertExpectations(t)

	// 10 events, 1 batch
	initTest()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()
	deleteSqsMessages(streamTestSqsClient, [][]*string{
		make([]*string, 10),
	})
	streamTestSqsClient.AssertExpectations(t)

	// 10 events, 1 batch, 2 sets
	initTest()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()
	deleteSqsMessages(streamTestSqsClient, [][]*string{
		make([]*string, 5),
		make([]*string, 5),
	})
	streamTestSqsClient.AssertExpectations(t)

	// 11 events, 2 batches
	initTest()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Times(2)
	deleteSqsMessages(streamTestSqsClient, [][]*string{
		make([]*string, 11),
	})
	streamTestSqsClient.AssertExpectations(t)

	// 11 events, 2 batches, 2 sets
	initTest()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Times(2)
	deleteSqsMessages(streamTestSqsClient, [][]*string{
		make([]*string, 10),
		make([]*string, 1),
	})
	streamTestSqsClient.AssertExpectations(t)

	// 100 events, 10 batches
	initTest()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Times(10)
	deleteSqsMessages(streamTestSqsClient, [][]*string{
		make([]*string, 100),
	})
	streamTestSqsClient.AssertExpectations(t)
}

func initTest() {
	common.Config.AwsLambdaFunctionMemorySize = 1024
	common.Config.SqsQueueURL = "https://fakesqsurl"
	streamTestSqsClient = &mockSQS{}
	streamTestDeadline = time.Now().Add(defaultTestTimeLimit)
}

func noopProcessorFunc(streamChan chan *common.DataStream, dest destinations.Destination) error {
	// drain channel
	for range streamChan {

	}
	return nil
}

// simulates error processing the data in a file
func failProcessorFunc(streamChan chan *common.DataStream, dest destinations.Destination) error {
	return fmt.Errorf("processError")
}

func noopReadSnsMessagesFunc(messages []string) ([]*common.DataStream, error) {
	return make([]*common.DataStream, len(messages)), nil
}

// simulated error parsing sqs message or reading s3 object
func failReadSnsMessagesFunc(messages []string) ([]*common.DataStream, error) {
	return nil, fmt.Errorf("readEventError")
}

type mockSQS struct {
	sqsiface.SQSAPI
	mock.Mock
}

func (m *mockSQS) DeleteMessageBatch(input *sqs.DeleteMessageBatchInput) (*sqs.DeleteMessageBatchOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.DeleteMessageBatchOutput), args.Error(1)
}

func (m *mockSQS) ReceiveMessage(input *sqs.ReceiveMessageInput) (*sqs.ReceiveMessageOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.ReceiveMessageOutput), args.Error(1)
}

func (m *mockSQS) GetQueueAttributes(input *sqs.GetQueueAttributesInput) (*sqs.GetQueueAttributesOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.GetQueueAttributesOutput), args.Error(1)
}
