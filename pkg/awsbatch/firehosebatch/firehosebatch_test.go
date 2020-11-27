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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestRetrySendInCaseOfError(t *testing.T) {
	t.Parallel()
	mockClient := &testutils.FirehoseMock{}
	input := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
	}
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &input, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, errors.New("failure")).Times(3)

	require.Error(t, Send(context.Background(), mockClient, input, 2))
	mockClient.AssertExpectations(t)
}

func TestDoNotRetrySendIfContextCancelled(t *testing.T) {
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

func TestRetrySendIfPartialFailure(t *testing.T) {
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

	require.NoError(t, Send(context.Background(), mockClient, input, 2))
	mockClient.AssertExpectations(t)
}

func TestSendFailIfPartialRetriesFailed(t *testing.T) {
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

	require.Error(t, Send(context.Background(), mockClient, input, 2))
	mockClient.AssertExpectations(t)
}

func TestSendBatchBreakUpRequests(t *testing.T) {
	t.Parallel()
	mockClient := &testutils.FirehoseMock{}
	bigData := make([]byte, maxBytes-10)
	// These inputs are too big to send together, but can be sent separately
	totalInput := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records: []*firehose.Record{
			{Data: []byte("enough bytes to have the next request push us over")},
			{Data: bigData},
			{Data: []byte("smol")},
		},
	}
	batchOneInput := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records:            totalInput.Records[0:1],
	}
	batchTwoInput := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records:            totalInput.Records[1:3],
	}
	batchOneOutput := &firehose.PutRecordBatchOutput{
		RequestResponses: []*firehose.PutRecordBatchResponseEntry{
			{RecordId: aws.String("1")},
		},
	}
	batchTwoOutput := &firehose.PutRecordBatchOutput{
		RequestResponses: []*firehose.PutRecordBatchResponseEntry{
			{RecordId: aws.String("2")},
			{RecordId: aws.String("3")},
		},
	}
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &batchOneInput, mock.Anything).
		Return(batchOneOutput, nil)
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &batchTwoInput, mock.Anything).
		Return(batchTwoOutput, nil)

	tooBig, err := BatchSend(context.Background(), mockClient, totalInput, 10)
	assert.NoError(t, err)
	assert.Empty(t, tooBig)
	mockClient.AssertExpectations(t)
}

func TestSendBatchSkipsTooBig(t *testing.T) {
	t.Parallel()
	mockClient := &testutils.FirehoseMock{}
	bigData := make([]byte, maxBytes+10)
	// The middle input is too big, and should be skipped
	totalInput := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records: []*firehose.Record{
			{Data: []byte("small data")},
			{Data: bigData},
			{Data: []byte("smol")},
		},
	}
	batchOneInput := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records:            totalInput.Records[0:1],
	}
	batchTwoInput := firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream"),
		Records:            totalInput.Records[2:3],
	}
	batchOneOutput := &firehose.PutRecordBatchOutput{
		RequestResponses: []*firehose.PutRecordBatchResponseEntry{
			{
				RecordId: aws.String("1"),
			},
		},
	}
	batchTwoOutput := &firehose.PutRecordBatchOutput{
		RequestResponses: []*firehose.PutRecordBatchResponseEntry{
			{
				RecordId: aws.String("3"),
			},
		},
	}
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &batchOneInput, mock.Anything).
		Return(batchOneOutput, nil)
	mockClient.On("PutRecordBatchWithContext", mock.Anything, &batchTwoInput, mock.Anything).
		Return(batchTwoOutput, nil)

	tooBig, err := BatchSend(context.Background(), mockClient, totalInput, 10)
	assert.NoError(t, err)
	require.Len(t, tooBig, 1)
	assert.Equal(t, totalInput.Records[1], tooBig[0])
	mockClient.AssertExpectations(t)
}
