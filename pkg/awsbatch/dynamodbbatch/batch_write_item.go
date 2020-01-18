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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/cenkalti/backoff"
	"go.uber.org/zap"
)

// AWS limit: a single call to BatchWriteItem can comprise as many as 25 put or delete requests.
const maxBatchWriteItems = 25

type batchWriteRequest struct {
	client       dynamodbiface.DynamoDBAPI
	input        *dynamodb.BatchWriteItemInput
	successCount int // Total number of items that have been written successfully
}

// Count the number of items in the request map
func writeItemCount(m map[string][]*dynamodb.WriteRequest) int {
	result := 0
	for _, val := range m {
		result += len(val)
	}
	return result
}

// send is a wrapper around BatchWriteItem which satisfies backoff.Operation.
func (r *batchWriteRequest) send() error {
	itemCount := writeItemCount(r.input.RequestItems)
	zap.L().Debug("invoking dynamodb.BatchWriteItem", zap.Int("items", itemCount))
	response, err := r.client.BatchWriteItem(r.input)

	if err != nil {
		// This was a service error - it can sometimes be retried
		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			case dynamodb.ErrCodeInternalServerError, dynamodb.ErrCodeProvisionedThroughputExceededException:
				zap.L().Warn("backoff: table temporarily unavailable", zap.Error(awsErr))
				return awsErr
			}
		}
		return &backoff.PermanentError{Err: err}
	}

	r.successCount += itemCount

	// Some subset of the items failed - retry only the failed items
	if len(response.UnprocessedItems) > 0 {
		failedCount := writeItemCount(response.UnprocessedItems)
		r.successCount -= failedCount
		err = fmt.Errorf("%d unprocessed items", failedCount)
		zap.L().Warn("backoff: batch write failed", zap.Error(err))
		r.input.RequestItems = response.UnprocessedItems
		return err
	}

	return nil
}

func logError(success int, failed int, err error) {
	zap.L().Error(
		"BatchWriteItem permanently failed",
		zap.Int("successItemCount", success),
		zap.Int("failedItemCount", failed),
		zap.Error(err),
	)
}

// BatchWriteItem writes items to Dynamo with paging, backoff, and auto-retry for failed items.
func BatchWriteItem(
	client dynamodbiface.DynamoDBAPI,
	maxElapsedTime time.Duration,
	input *dynamodb.BatchWriteItemInput,
) error {

	totalItems := writeItemCount(input.RequestItems)
	zap.L().Info("starting dynamodbbatch.BatchWriteItem", zap.Int("totalItems", totalItems))
	start := time.Now()

	config := backoff.NewExponentialBackOff()
	config.MaxElapsedTime = maxElapsedTime
	allItems := input.RequestItems
	request := &batchWriteRequest{client: client, input: input}

	// Break items into multiple requests as necessary
	input.RequestItems = make(map[string][]*dynamodb.WriteRequest)
	itemCount := 0
	for tableName, items := range allItems {
		for _, item := range items {
			input.RequestItems[tableName] = append(input.RequestItems[tableName], item)
			itemCount++

			if itemCount == maxBatchWriteItems {
				// Send a full batch of items
				if err := backoff.Retry(request.send, config); err != nil {
					logError(request.successCount, totalItems-request.successCount, err)
					return err
				}
				input.RequestItems = make(map[string][]*dynamodb.WriteRequest)
				itemCount = 0
			}
		}
	}

	if itemCount > 0 {
		if err := backoff.Retry(request.send, config); err != nil {
			logError(request.successCount, totalItems-request.successCount, err)
			return err
		}
	}

	zap.L().Info("BatchWriteItem successful", zap.Duration("duration", time.Since(start)))
	return nil
}
