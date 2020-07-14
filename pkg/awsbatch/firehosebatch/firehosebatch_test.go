package firehosebatch

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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestRetryInCaseOfError(t *testing.T) {
	t.Parallel()
	mockClient := &testutils.FirehoseMock{}
	input := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
	}
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &input, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, errors.New("failure")).Times(3)

	require.Error(t, Send(context.TODO(), mockClient, input, 2))
	mockClient.AssertExpectations(t)
}

func TestDoNotRetryIfContextCancelled(t *testing.T) {
	t.Parallel()
	mockClient := &testutils.FirehoseMock{}
	input := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
	}
	ctx, cancelFun := context.WithCancel(context.Background())
	// Cancelling the context. We shouldn't retry
	cancelFun()
	// This operation should run only once - we shouldn't retry since context has been cancelled
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &input, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, errors.New("failure")).Once()

	require.Error(t, Send(ctx, mockClient, input, 2))
	mockClient.AssertExpectations(t)
}

func TestRetryIfPartialFailure(t *testing.T) {
	t.Parallel()
	mockClient := &testutils.FirehoseMock{}
	input := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records: []*firehose.Record{
			{
				Data: []byte("record1"),
			},
			{
				Data: []byte("record2"),
			},
		},
	}
	partialFailureOutput := &firehose.PutRecordBatchOutput{
		FailedPutCount: aws.Int64(1),
		RequestResponses: []*firehose.PutRecordBatchResponseEntry{
			{
				RecordId: aws.String("1"), //  record succeeded
			},
			{
				ErrorCode: aws.String("error"), // record failed
			},
		},
	}
	partialRequestInput := &firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records: []*firehose.Record{
			{
				Data: []byte("record2"),
			},
		},
	}
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &input, mock.Anything).
		Return(partialFailureOutput, nil).Once()
	mockClient.On("PutRecordBatchWithContext", mock.Anything, partialRequestInput, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, nil).Once()

	require.NoError(t, Send(context.TODO(), mockClient, input, 2))
	mockClient.AssertExpectations(t)
}

func TestFailIfPartialRetriesFailed(t *testing.T) {
	t.Parallel()
	mockClient := &testutils.FirehoseMock{}
	input := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records: []*firehose.Record{
			{
				Data: []byte("record"),
			},
		},
	}
	partialFailureOutput := &firehose.PutRecordBatchOutput{
		FailedPutCount: aws.Int64(1),
		RequestResponses: []*firehose.PutRecordBatchResponseEntry{
			{
				ErrorCode: aws.String("error"), // record failed
			},
		},
	}
	partialRequestInput := &firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records: []*firehose.Record{
			{
				Data: []byte("record"),
			},
		},
	}
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &input, mock.Anything).
		Return(partialFailureOutput, nil).Once()
	mockClient.On("PutRecordBatchWithContext", mock.Anything, partialRequestInput, mock.Anything).
		Return(partialFailureOutput, nil).Twice()

	require.Error(t, Send(context.TODO(), mockClient, input, 2))
	mockClient.AssertExpectations(t)
}
