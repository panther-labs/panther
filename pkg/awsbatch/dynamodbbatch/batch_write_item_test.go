package dynamodbbatch

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"
)

const mockTableName = "test-table-name"

type mockDynamo struct {
	dynamodbiface.DynamoDBAPI
	unprocessedItems bool  // If True, only the first item in each batch will succeed
	err              error // If AWS error, it will only trigger the first time
	callCount        int   // Counts the number of PutRecords calls for tests to verify
}

func (m *mockDynamo) BatchWriteItem(in *dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error) {
	m.callCount++

	if m.unprocessedItems && len(in.RequestItems[mockTableName]) > 1 {
		return &dynamodb.BatchWriteItemOutput{
			UnprocessedItems: map[string][]*dynamodb.WriteRequest{
				mockTableName: in.RequestItems[mockTableName][1:], // only first item succeeds
			},
		}, m.err
	}

	returnErr := m.err
	if _, ok := m.err.(awserr.Error); ok {
		m.err = nil // The next call will not return a temporary AWS error
	}
	return &dynamodb.BatchWriteItemOutput{}, returnErr
}

func mockWriteInput() *dynamodb.BatchWriteItemInput {
	return &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{
			mockTableName: {
				&dynamodb.WriteRequest{PutRequest: &dynamodb.PutRequest{}},
				&dynamodb.WriteRequest{PutRequest: &dynamodb.PutRequest{}},
			},
		},
	}
}

func TestWriteItemCount(t *testing.T) {
	items := map[string][]*dynamodb.WriteRequest{
		"table1": make([]*dynamodb.WriteRequest, 2),
		"table2": make([]*dynamodb.WriteRequest, 3),
		"table3": make([]*dynamodb.WriteRequest, 5),
	}
	assert.Equal(t, 10, writeItemCount(items))
}

func TestBatchWriteItem(t *testing.T) {
	client := &mockDynamo{}
	assert.Nil(t, BatchWriteItem(client, 5*time.Second, mockWriteInput()))
	assert.Equal(t, 1, client.callCount)
}

// Unprocessed items are retried
func TestBatchWriteItemBackoff(t *testing.T) {
	client := &mockDynamo{unprocessedItems: true}
	assert.Nil(t, BatchWriteItem(client, 5*time.Second, mockWriteInput()))
	assert.Equal(t, 2, client.callCount)
}

// An unusual error is not retried
func TestBatchWriteItemPermanentError(t *testing.T) {
	client := &mockDynamo{err: errors.New("permanent")}
	assert.NotNil(t, BatchWriteItem(client, 5*time.Second, mockWriteInput()))
	assert.Equal(t, 1, client.callCount)
}

// A temporary error is retried
func TestBatchWriteItemTemporaryError(t *testing.T) {
	client := &mockDynamo{
		err: awserr.New(dynamodb.ErrCodeInternalServerError, "try again later", nil),
	}
	assert.Nil(t, BatchWriteItem(client, 5*time.Second, mockWriteInput()))
	assert.Equal(t, 2, client.callCount)
}

// A large number of records are broken into multiple requests
func TestBatchWriteItemPaging(t *testing.T) {
	input := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{
			"table1": make([]*dynamodb.WriteRequest, maxBatchWriteItems),
			"table2": make([]*dynamodb.WriteRequest, maxBatchWriteItems+1),
		},
	}
	client := &mockDynamo{}
	assert.Nil(t, BatchWriteItem(client, 5*time.Second, input))
	assert.Equal(t, 3, client.callCount)
}
