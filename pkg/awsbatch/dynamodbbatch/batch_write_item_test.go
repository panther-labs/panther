package dynamodbbatch

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
