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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// AWS limit: each SendMessageBatch request contains at most 10 items and 262144 bytes
// Setting max bytes below the AWS max because I'm not 100% sure how much overhead the rest of the
// headers AWS adds is, or if it matters or is constant
const (
	maxMessages     = 10
	maxMessageBytes = 260000
)

type sendMessageBatchRequest struct {
	client       sqsiface.SQSAPI
	input        *sqs.SendMessageBatchInput
	successCount int // Total number of messages that sent successfully across all requests
}

// send is a wrapper around sqs.SendMessageBatch which satisfies backoff.Operation.
func (r *sendMessageBatchRequest) send() error {
	zap.L().Debug("invoking sqs.SendMessageBatch", zap.Int("entries", len(r.input.Entries)))
	response, err := r.client.SendMessageBatch(r.input)

	if err != nil {
		// There are no transient error types here that can be retried
		return &backoff.PermanentError{Err: err}
	}

	r.successCount += len(response.Successful)

	// Some subset of the entries failed - retry only the failed ones
	if len(response.Failed) > 0 {
		err = fmt.Errorf("%d unprocessed items", len(response.Failed))
		zap.L().Warn("backoff: batch send failed", zap.Error(err))

		// Get the set of failed message IDs
		retryIDs := make(map[string]bool)
		for _, failedEntry := range response.Failed {
			retryIDs[*failedEntry.Id] = true
		}

		// Put the failed message IDs back in the input
		var retryEntries []*sqs.SendMessageBatchRequestEntry
		for _, entry := range r.input.Entries {
			if retryIDs[*entry.Id] {
				retryEntries = append(retryEntries, entry)
			}
		}
		r.input.Entries = retryEntries
		return err
	}

	return nil
}

// SendMessageBatch sends messages to SQS with paging, backoff, and auto-retry for failed items.
func SendMessageBatch(
	client sqsiface.SQSAPI,
	maxElapsedTime time.Duration,
	input *sqs.SendMessageBatchInput,
) ([]*sqs.SendMessageBatchRequestEntry, error) {

	zap.L().Info("starting sqsbatch.SendMessageBatch", zap.Int("totalEntries", len(input.Entries)))
	start := time.Now()

	config := backoff.NewExponentialBackOff()
	config.MaxElapsedTime = maxElapsedTime
	allEntries := input.Entries
	request := &sendMessageBatchRequest{client: client, input: input}
	// Messages that would be too big to send if we tried to send them
	bigMessages := make([]*sqs.SendMessageBatchRequestEntry, 0)

	// Break records into multiple requests as necessary
	for i := 0; i < len(allEntries); {
		input.Entries = make([]*sqs.SendMessageBatchRequestEntry, 0, maxMessages)
		currentBatchSize := 0
		for {
			entrySize := len(aws.StringValue(allEntries[i].MessageBody))
			// Sometimes a single entry can be too big to send. In this case, don't even try and just return the
			// over sized message to the requester so they can handle it how they see fit
			if entrySize > maxMessageBytes {
				bigMessages = append(bigMessages, allEntries[i])
			} else {
				input.Entries = append(input.Entries, allEntries[i])
				currentBatchSize += entrySize
			}
			i++

			// If this is not the last entry, check the size of the next entry. If this is the last
			// entry, break
			nextItemSize := 0
			if i < len(allEntries) {
				nextItemSize = len(aws.StringValue(allEntries[i].MessageBody))
			} else {
				break
			}

			// Check if the next entry would push us over the max message count, or the next
			// entry would push us over the max message byte size
			if len(input.Entries) == maxMessages || currentBatchSize+nextItemSize >= maxMessageBytes {
				break
			}
		}

		// This only happens when at the start of this iteration all remaining items are over sized (most common when
		// only one item is being sent and it's over sized)
		if len(request.input.Entries) == 0 {
			break
		}
		// This case covers when some entries failed to send because of unrecoverable issues
		if err := backoff.Retry(request.send, config); err != nil {
			zap.L().Error(
				"SendMessageBatch permanently failed",
				zap.Int("sentMessageCount", request.successCount),
				zap.Int("failedMessageCount", len(allEntries)-request.successCount),
				zap.Error(err),
			)
			return allEntries[request.successCount:], err
		}
	}

	// This case covers when some entries would have failed to send if we tried, so we didn't try
	if len(bigMessages) > 0 {
		zap.L().Info(
			"SendMessageBatch partially successful",
			zap.Duration("duration", time.Since(start)),
			zap.Int("failures", len(bigMessages)),
		)
		return bigMessages, errors.New(sqs.ErrCodeBatchRequestTooLong)
	}

	// This case covers when all entries sent successfully
	zap.L().Info("SendMessageBatch successful", zap.Duration("duration", time.Since(start)))
	return nil, nil
}
