package sqsbatch

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
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/assert"
)

type mockSQS struct {
	sqsiface.SQSAPI
	unprocessedItems bool // If True, only the first item in each batch will succeed
	err              error
	callCount        int // Counts the number of PutRecords calls for tests to verify
}

func (m *mockSQS) SendMessageBatch(input *sqs.SendMessageBatchInput) (*sqs.SendMessageBatchOutput, error) {
	m.callCount++

	if m.err != nil {
		return nil, m.err
	}

	if len(input.GoString()) > maxBytes {
		return nil, errors.New(sqs.ErrCodeBatchRequestTooLong)
	}

	result := &sqs.SendMessageBatchOutput{}
	for i, entry := range input.Entries {
		if i == 0 || !m.unprocessedItems {
			// Success if this is first record or failure not requested
			result.Successful = append(result.Successful, &sqs.SendMessageBatchResultEntry{Id: entry.Id})
		} else {
			// All other records fail
			result.Failed = append(result.Failed, &sqs.BatchResultErrorEntry{Id: entry.Id})
		}
	}

	return result, nil
}

func testInput() *sqs.SendMessageBatchInput {
	return &sqs.SendMessageBatchInput{
		Entries: []*sqs.SendMessageBatchRequestEntry{
			{Id: aws.String("first"), MessageBody: aws.String("hello")},
			{Id: aws.String("second"), MessageBody: aws.String("world")},
		},
		QueueUrl: aws.String("test-queue-url"),
	}
}

func TestSendMessageBatch(t *testing.T) {
	client := &mockSQS{}
	assert.NoError(t, SendMessageBatch(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// Unprocessed items are retried
func TestSendMessageBatchBackoff(t *testing.T) {
	client := &mockSQS{unprocessedItems: true}
	assert.NoError(t, SendMessageBatch(client, 5*time.Second, testInput()))
	assert.Equal(t, 2, client.callCount)
}

// Client errors are not retried
func TestSendMessageBatchPermanentError(t *testing.T) {
	client := &mockSQS{err: errors.New("permanent")}
	assert.Error(t, SendMessageBatch(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// a large number of records are broken into multiple requests
func TestSendMessageBatchLargePagination(t *testing.T) {
	client := &mockSQS{}
	firstBody := ""
	secondBody := ""
	thirdBody := ""

	// maxByteSize is 260,000 bytes, each of these three is 100,000
	// this will force a cutoff due to size after the second entry
	for ; len(firstBody) < 100000; firstBody += "hello" {
	}
	for ; len(secondBody) < 100000; secondBody += "world" {
	}
	for ; len(thirdBody) < 100000; thirdBody += "large" {
	}

	input := &sqs.SendMessageBatchInput{
		Entries: []*sqs.SendMessageBatchRequestEntry{
			{Id: aws.String("first"), MessageBody: aws.String(firstBody)},
			{Id: aws.String("second"), MessageBody: aws.String(secondBody)},
			{Id: aws.String("third"), MessageBody: aws.String(thirdBody)},
		},
		QueueUrl: aws.String("test-queue-url"),
	}

	assert.NoError(t, SendMessageBatch(client, 5*time.Second, input))
	assert.Equal(t, 2, client.callCount)
}

// a single request that is too large will error
func TestSendMessageBatchLargePaginationError(t *testing.T) {
	client := &mockSQS{}
	secondBody := ""

	// maxByteSize is 260,000 bytes, so the second entry will be too large and error
	for ; len(secondBody) < 300000; secondBody += "world" {
	}

	input := &sqs.SendMessageBatchInput{
		Entries: []*sqs.SendMessageBatchRequestEntry{
			{Id: aws.String("first"), MessageBody: aws.String("hello")},
			{Id: aws.String("second"), MessageBody: aws.String(secondBody)},
			{Id: aws.String("third"), MessageBody: aws.String("large")},
		},
		QueueUrl: aws.String("test-queue-url"),
	}

	assert.Error(t, SendMessageBatch(client, 5*time.Second, input))
	assert.Equal(t, 2, client.callCount)
}

// A small number of records that are large are broken into multiple requests
func TestSendMessageBatchPagination(t *testing.T) {
	client := &mockSQS{}
	entries := make([]*sqs.SendMessageBatchRequestEntry, 2*maxMessages+1)
	for i := 0; i < len(entries); i++ {
		entries[i] = &sqs.SendMessageBatchRequestEntry{Id: aws.String(strconv.Itoa(i))}
	}
	input := &sqs.SendMessageBatchInput{Entries: entries}

	assert.NoError(t, SendMessageBatch(client, 5*time.Second, input))
	assert.Equal(t, 3, client.callCount)
}
