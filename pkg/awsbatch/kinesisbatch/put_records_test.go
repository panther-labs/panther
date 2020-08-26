package kinesisbatch

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
	"strconv"
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
				SequenceNumber: aws.String(strconv.Itoa(i)),
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
	t.Parallel()
	client := &mockKinesis{}
	assert.Nil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// Unprocessed items are retried
func TestPutRecordsBackoff(t *testing.T) {
	t.Parallel()
	client := &mockKinesis{unprocessedItems: true}
	assert.Nil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 2, client.callCount)
}

// An unusual error is not retried
func TestPutRecordsPermanentError(t *testing.T) {
	t.Parallel()
	client := &mockKinesis{err: errors.New("permanent")}
	assert.NotNil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// A temporary error is retried
func TestPutRecordsTemporaryError(t *testing.T) {
	t.Parallel()
	client := &mockKinesis{
		err: awserr.New(kinesis.ErrCodeProvisionedThroughputExceededException, "try again later", nil),
	}
	assert.Nil(t, PutRecords(client, 5*time.Second, testInput()))
	assert.Equal(t, 2, client.callCount)
}

// A large number of records are broken into multiple requests
func TestPutRecordsPagination(t *testing.T) {
	t.Parallel()
	client := &mockKinesis{}
	input := &kinesis.PutRecordsInput{
		Records: make([]*kinesis.PutRecordsRequestEntry, maxRecords*2+1),
	}
	assert.Nil(t, PutRecords(client, 5*time.Second, input))
	assert.Equal(t, 3, client.callCount)
}
