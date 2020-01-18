package kinesisbatch

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/aws/aws-sdk-go/service/kinesis/kinesisiface"
	"github.com/stretchr/testify/assert"
)

type mockKinesis struct {
	kinesisiface.KinesisAPI
	unprocessedItems bool  // If True, only the first item in each batch will succeed
	err              error // If AWS error, it will only trigger the first time
	callCount        int   // Counts the number of PutRecords calls for tests to verify
}

func (m *mockKinesis) PutRecords(input *kinesis.PutRecordsInput) (*kinesis.PutRecordsOutput, error) {
	m.callCount++

	if m.err != nil {
		returnErr := m.err
		if _, ok := m.err.(awserr.Error); ok {
			m.err = nil // The next call will not return a temporary AWS error
		}
		return nil, returnErr
	}

	result := &kinesis.PutRecordsOutput{FailedRecordCount: aws.Int64(0)}
	for i := range input.Records {
		if i == 0 || !m.unprocessedItems {
			// Success if this is first record or failure not requested
			result.Records = append(result.Records, &kinesis.PutRecordsResultEntry{
				SequenceNumber: aws.String(string(i)),
				ShardId:        aws.String("shard-id"),
			})
		} else {
			// All other records fail
			*result.FailedRecordCount++
			result.Records = append(result.Records, &kinesis.PutRecordsResultEntry{
				ErrorCode:    aws.String("ProvisionedThroughputExceededException"),
				ErrorMessage: aws.String("slow down!"),
			})
		}
	}
	return result, nil
}

func testInput() *kinesis.PutRecordsInput {
	return &kinesis.PutRecordsInput{
		Records: []*kinesis.PutRecordsRequestEntry{
			{Data: []byte("hello")},
			{Data: []byte("world")},
		},
		StreamName: aws.String("test-stream-name"),
	}
}

func TestPutRecords(t *testing.T) {
	client := &mockKinesis{}
	assert.Nil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// Unprocessed items are retried
func TestPutRecordsBackoff(t *testing.T) {
	client := &mockKinesis{unprocessedItems: true}
	assert.Nil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 2, client.callCount)
}

// An unusual error is not retried
func TestPutRecordsPermanentError(t *testing.T) {
	client := &mockKinesis{err: errors.New("permanent")}
	assert.NotNil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// A temporary error is retried
func TestPutRecordsTemporaryError(t *testing.T) {
	client := &mockKinesis{
		err: awserr.New(kinesis.ErrCodeProvisionedThroughputExceededException, "try again later", nil),
	}
	assert.Nil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 2, client.callCount)
}

// A large number of records are broken into multiple requests
func TestPutRecordsPagination(t *testing.T) {
	client := &mockKinesis{}
	input := &kinesis.PutRecordsInput{
		Records: make([]*kinesis.PutRecordsRequestEntry, maxRecords*2+1),
	}
	assert.Nil(t, PutRecords(client, 5*time.Second, input))
	assert.Equal(t, 3, client.callCount)
}
