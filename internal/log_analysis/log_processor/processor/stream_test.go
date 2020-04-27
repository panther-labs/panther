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
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
)

const (
	defaultTestTimeLimitSec = 2
)

var (
	streamTestTime time.Time

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
				Body: aws.String(snsMessage),
			},
		},
	}
)

func TestStreamEventsLambdaPlusSQS(t *testing.T) {
	// lambda events and sqs events
	initTest()

	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()
	// this one has no messages, which breaks the loop
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{}, nil).Once()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestTime, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records)+len(streamTestReceiveMessageOutput.Messages), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsOnlyLambda(t *testing.T) {
	// only lambda events
	initTest()

	// this one has no messages, which breaks the loop
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{}, nil).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestTime, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsProcessingTimeLimitExceeded(t *testing.T) {
	initTest()

	// should only process the lambda events although there are sqs events in the q cuz of timeout
	common.Config.TimeLimitSec = 0 // polling loop should not be entered

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestTime, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records), sqsMessageCount)
	streamTestSqsClient.AssertExpectations(t)
}

func TestStreamEventsReadEventError(t *testing.T) {
	initTest()

	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil)
	// this one has no messages, which breaks the loop
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{}, nil)
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil)

	_, err := streamEvents(streamTestSqsClient, streamTestTime, streamTestLambdaEvent,
		noopProcessorFunc, failReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "readEventError", err.Error())
}

func TestStreamEventsProcessError(t *testing.T) {
	initTest()

	common.Config.TimeLimitSec = 0 // ensure sqs reading go routine exits quickly to avoid data races between tests

	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil)
	// this one has no messages, which breaks the loop
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{}, nil)
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil)

	_, err := streamEvents(streamTestSqsClient, streamTestTime, streamTestLambdaEvent,
		failProcessorFunc, noopReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error())
}

func TestStreamEventsProcessErrorAndReadEventError(t *testing.T) {
	initTest()

	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil)
	// this one has no messages, which breaks the loop
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{}, nil)
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil)

	_, err := streamEvents(streamTestSqsClient, streamTestTime, streamTestLambdaEvent,
		failProcessorFunc, failReadSnsMessagesFunc)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error()) // expect the processError NOT readEventError
}

func TestStreamEventsDeleteSQSError(t *testing.T) {
	initTest()

	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(streamTestReceiveMessageOutput, nil).Once()
	// this one has no messages, which breaks the loop
	streamTestSqsClient.On("ReceiveMessage", mock.Anything).Return(&sqs.ReceiveMessageOutput{}, nil).Once()
	streamTestSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{},
		fmt.Errorf("deleteError")).Once()

	sqsMessageCount, err := streamEvents(streamTestSqsClient, streamTestTime, streamTestLambdaEvent,
		noopProcessorFunc, noopReadSnsMessagesFunc)
	assert.Error(t, err)
	assert.Equal(t, len(streamTestLambdaEvent.Records)+len(streamTestReceiveMessageOutput.Messages), sqsMessageCount)
	assert.Equal(t, "failure deleting messages from https://fakesqsurl: deleteError", err.Error())
	streamTestSqsClient.AssertExpectations(t)
}

func initTest() {
	common.Config.AwsLambdaFunctionMemorySize = 1024
	common.Config.TimeLimitSec = defaultTestTimeLimitSec
	common.Config.SqsQueueURL = "https://fakesqsurl"
	streamTestSqsClient = &mockSQS{}
	streamTestTime = time.Now()
	maxContiguousEmptyReads = 0
}

func noopProcessorFunc(streamChan chan *common.DataStream, dest destinations.Destination) error {
	// drain channel
	for range streamChan {

	}
	return nil
}

func failProcessorFunc(streamChan chan *common.DataStream, dest destinations.Destination) error {
	return fmt.Errorf("processError")
}

func noopReadSnsMessagesFunc(messages []string) ([]*common.DataStream, error) {
	return make([]*common.DataStream, len(messages)), nil
}

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
