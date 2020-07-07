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

	if len(input.GoString()) > maxMessageBytes {
		return nil, errors.New(sqs.ErrCodeBatchRequestTooLong)
	}

	result := &sqs.SendMessageBatchOutput{}
	for i, entry := range input.Entries {
		if i == 0 || !m.unprocessedItems {
			// Success if this is first record or failure not requested
			result.Successful = append(result.Successful, &sqs.SendMessageBatchResultEntry{Id: entry.Id})
		} else {
			// All other records fail
			result.Failed = append(result.Failed, &sqs.BatchResultErrorEntry{
				Id:      entry.Id,
				Message: aws.String("test error"),
			})
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
	t.Parallel()
	client := &mockSQS{}
	failures, err := SendMessageBatch(client, 5*time.Second, testInput())
	assert.NoError(t, err)
	assert.Empty(t, failures)
	assert.Equal(t, 1, client.callCount)
}

// Unprocessed items are retried
func TestSendMessageBatchBackoff(t *testing.T) {
	t.Parallel()
	client := &mockSQS{unprocessedItems: true}
	failures, err := SendMessageBatch(client, 5*time.Second, testInput())
	assert.NoError(t, err)
	assert.Empty(t, failures)
	assert.Equal(t, 2, client.callCount)
}

// Client errors are not retried
func TestSendMessageBatchPermanentError(t *testing.T) {
	t.Parallel()
	client := &mockSQS{err: errors.New("permanent")}
	failures, err := SendMessageBatch(client, 5*time.Second, testInput())
	assert.Error(t, err)
	assert.Len(t, failures, 2)
	assert.Equal(t, 1, client.callCount)
}

// a large number of records are broken into multiple requests
func TestSendMessageBatchLargePagination(t *testing.T) {
	t.Parallel()
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

	failures, err := SendMessageBatch(client, 5*time.Second, input)
	assert.NoError(t, err)
	assert.Empty(t, failures)
	assert.Equal(t, 2, client.callCount)
}

// a single request that is too large will error
func TestSendMessageBatchLargePaginationError(t *testing.T) {
	t.Parallel()
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

	failures, err := SendMessageBatch(client, 5*time.Second, input)
	assert.Error(t, err)
	assert.Equal(t, sqs.ErrCodeBatchRequestTooLong, err.Error())
	assert.Len(t, failures, 1)
	assert.Equal(t, 2, client.callCount)
}

// A small number of records that are large are broken into multiple requests
func TestSendMessageBatchPagination(t *testing.T) {
	t.Parallel()
	client := &mockSQS{}
	entries := make([]*sqs.SendMessageBatchRequestEntry, 2*maxMessages+1)
	for i := 0; i < len(entries); i++ {
		entries[i] = &sqs.SendMessageBatchRequestEntry{Id: aws.String(strconv.Itoa(i))}
	}
	input := &sqs.SendMessageBatchInput{Entries: entries}

	failures, err := SendMessageBatch(client, 5*time.Second, input)
	assert.NoError(t, err)
	assert.Empty(t, failures)
	assert.Equal(t, 3, client.callCount)
}
