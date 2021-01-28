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
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	streamTestReceiveMessageOutput = &sqs.ReceiveMessageOutput{
		Messages: []*sqs.Message{
			{
				Body:          aws.String("{}"), // empty JSON is fine
				ReceiptHandle: aws.String("testMessageHandle"),
			},
		},
	}
)

func init() {
	// set these once at start of test
	common.Config.AwsLambdaFunctionMemorySize = 1024
	common.Config.SqsQueueURL = "https://fakesqsurl"
	getObjectMock := &testutils.CounterMock{}
	getObjectMock.On("With", mock.Anything).Return(getObjectMock).Maybe()
	getObjectMock.On("Add", mock.Anything).Maybe()
	common.GetObject = getObjectMock
}

func TestStreamEvents(t *testing.T) {
	t.Parallel()
	sqsMock := &testutils.SqsMock{}
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestReceiveMessageOutput, nil).Once()
	// this one return 0 messages, which breaks the loop
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&sqs.ReceiveMessageOutput{}, nil).Once()
	sqsMock.On("DeleteMessageBatch", mock.Anything).
		Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	count, err := pollEvents(ctx, sqsMock, noopProcessorFunc, noopGenerateDataStream)
	require.NoError(t, err)
	assert.Equal(t, len(streamTestReceiveMessageOutput.Messages), count)

	sqsMock.AssertExpectations(t)
}

func TestStreamEventsProcessingTimeLimitExceeded(t *testing.T) {
	t.Parallel()
	sqsMock := &testutils.SqsMock{}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now()) // set to current time so code exits immediately
	defer cancel()
	count, err := pollEvents(ctx, sqsMock, noopProcessorFunc, noopGenerateDataStream)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	sqsMock.AssertExpectations(t)
}

func TestStreamEventsReadEventError(t *testing.T) {
	t.Parallel()
	sqsMock := &testutils.SqsMock{}
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestReceiveMessageOutput, nil).Once()
	// Empty result should cause polling to stop
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&sqs.ReceiveMessageOutput{}, nil).Once()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	count, err := pollEvents(ctx, sqsMock, noopProcessorFunc, failGenerateDataStream)
	// Failure in the generateDataStreamsFunc should no cause the function invocation to fail
	// but we shouldn't invoke the DeleteBatch operation neither since the messages haven't been processed
	require.NoError(t, err)
	require.Equal(t, 0, count)

	sqsMock.AssertExpectations(t)
}

func TestStreamEventsProcessError(t *testing.T) {
	t.Parallel()
	sqsMock := &testutils.SqsMock{}
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestReceiveMessageOutput, nil).Once()
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&sqs.ReceiveMessageOutput{}, nil).Once() // this one return 0 messages, which breaks the loop

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	count, err := pollEvents(ctx, sqsMock, failProcessorFunc, noopGenerateDataStream)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error())
	require.Equal(t, 0, count)

	sqsMock.AssertExpectations(t)
}

func TestStreamEventsProcessErrorAndReadEventError(t *testing.T) {
	t.Parallel()
	sqsMock := &testutils.SqsMock{}
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestReceiveMessageOutput, nil).Once() // Should be called only once because operation fails
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&sqs.ReceiveMessageOutput{}, nil).Once() // this one return 0 messages, which breaks the loop

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	count, err := pollEvents(ctx, sqsMock, failProcessorFunc, failGenerateDataStream)
	require.Error(t, err)
	assert.Equal(t, "processError", err.Error())
	require.Equal(t, 0, count)

	sqsMock.AssertExpectations(t)
}

func TestStreamEventsReceiveSQSError(t *testing.T) {
	t.Parallel()
	sqsMock := &testutils.SqsMock{}
	// this one succeeds
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestReceiveMessageOutput, nil).Once()
	// this one fails
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&sqs.ReceiveMessageOutput{}, fmt.Errorf("receiveError")).Once()

	// Should invoce delete on the first batch
	sqsMock.On("DeleteMessageBatch", mock.Anything).
		Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	count, err := pollEvents(ctx, sqsMock, noopProcessorFunc, noopGenerateDataStream)
	assert.NoError(t, err)
	require.Equal(t, len(streamTestReceiveMessageOutput.Messages), count)

	sqsMock.AssertExpectations(t)
}

func TestStreamEventsDeleteSQSError(t *testing.T) {
	sqsMock := &testutils.SqsMock{}

	logs := mockLogger()

	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestReceiveMessageOutput, nil).Once()
	// this one is below threshold, which breaks the loop
	sqsMock.On("ReceiveMessageWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&sqs.ReceiveMessageOutput{}, nil).Once()

	// this one fails
	sqsMock.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{
		Failed:     []*sqs.BatchResultErrorEntry{{}},
		Successful: []*sqs.DeleteMessageBatchResultEntry{},
	}, fmt.Errorf("deleteError")).Once()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	count, err := pollEvents(ctx, sqsMock, noopProcessorFunc, noopGenerateDataStream)

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
	assert.Equal(t, len(streamTestReceiveMessageOutput.Messages), count)
	assert.Equal(t, len(expectedLogs), len(actualLogs))
	for i := range expectedLogs {
		assertLogEqual(t, expectedLogs[i], actualLogs[i])
	}

	sqsMock.AssertExpectations(t)
}

func noopProcessorFunc(streamChan <-chan *common.DataStream, _ destinations.Destination) error {
	// drain channel
	for range streamChan {
	}
	return nil
}

// simulates error processing the data in a file
func failProcessorFunc(streamChan <-chan *common.DataStream, _ destinations.Destination) error {
	for range streamChan {
	}
	return fmt.Errorf("processError")
}

func noopGenerateDataStream(_ context.Context, _ string) ([]*common.DataStream, error) {
	src := &models.SourceIntegration{}
	src.IntegrationID = "id"
	return []*common.DataStream{
		{
			Source: src,
		},
	}, nil
}

// simulated error parsing sqs message or reading s3 object
func failGenerateDataStream(_ context.Context, _ string) ([]*common.DataStream, error) {
	return nil, fmt.Errorf("readEventError")
}
