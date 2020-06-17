package sqsbatch

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
	"testing"

	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestDeleteMessageBatch(t *testing.T) {
	t.Parallel()
	queueURL := "fakeqURL"

	// 1 event, 1 batch
	mockSqsClient := &testutils.SqsMock{}
	mockSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()
	DeleteMessageBatch(mockSqsClient, queueURL, make([]*string, 1))
	mockSqsClient.AssertExpectations(t)

	// 5 events, 1 batch
	mockSqsClient = &testutils.SqsMock{}
	mockSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()
	DeleteMessageBatch(mockSqsClient, queueURL, make([]*string, 5))
	mockSqsClient.AssertExpectations(t)

	// 10 events, 1 batch
	mockSqsClient = &testutils.SqsMock{}
	mockSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Once()
	DeleteMessageBatch(mockSqsClient, queueURL, make([]*string, 10))
	mockSqsClient.AssertExpectations(t)

	// 11 events, 2 batches
	mockSqsClient = &testutils.SqsMock{}
	mockSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Times(2)
	DeleteMessageBatch(mockSqsClient, queueURL, make([]*string, 11))
	mockSqsClient.AssertExpectations(t)

	// 100 events, 10 batches
	mockSqsClient = &testutils.SqsMock{}
	mockSqsClient.On("DeleteMessageBatch", mock.Anything).Return(&sqs.DeleteMessageBatchOutput{}, nil).Times(10)
	DeleteMessageBatch(mockSqsClient, queueURL, make([]*string, 100))
	mockSqsClient.AssertExpectations(t)
}
