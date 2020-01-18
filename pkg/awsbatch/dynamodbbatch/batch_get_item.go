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
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"go.uber.org/zap"
)

// AWS limit: a single call to BatchGetItem can include at most 100 items.
const maxBatchGetItems = 100

// Count the number of items in the request map
func getItemCount(m map[string]*dynamodb.KeysAndAttributes) int {
	result := 0
	for _, val := range m {
		result += len(val.Keys)
	}
	return result
}

// BatchGetItem reads multiple items from DynamoDB with paging of both the request and the response.
func BatchGetItem(
	client dynamodbiface.DynamoDBAPI,
	input *dynamodb.BatchGetItemInput,
) (*dynamodb.BatchGetItemOutput, error) {

	zap.L().Info("starting dynamodbbatch.BatchGetItem",
		zap.Int("totalItems", getItemCount(input.RequestItems)))
	start := time.Now()

	result := &dynamodb.BatchGetItemOutput{
		Responses: make(map[string][]map[string]*dynamodb.AttributeValue),
	}

	// Each page of results will be added to the final result set
	updateResult := func(page *dynamodb.BatchGetItemOutput, lastPage bool) bool {
		for tableName, attributes := range page.Responses {
			result.Responses[tableName] = append(result.Responses[tableName], attributes...)
		}
		return true // continue paginating
	}

	// Break items into multiple requests as necessary
	allItems := input.RequestItems
	input.RequestItems = make(map[string]*dynamodb.KeysAndAttributes)
	itemCount := 0
	for tableName, attrs := range allItems {
		for _, key := range attrs.Keys {
			if input.RequestItems[tableName] == nil {
				input.RequestItems[tableName] = allItems[tableName]
				input.RequestItems[tableName].Keys = nil
			}

			input.RequestItems[tableName].Keys = append(input.RequestItems[tableName].Keys, key)
			itemCount++
			if itemCount == maxBatchGetItems {
				// Send a full batch of requests
				if err := client.BatchGetItemPages(input, updateResult); err != nil {
					return nil, err
				}
				input.RequestItems = make(map[string]*dynamodb.KeysAndAttributes)
				itemCount = 0
			}
		}
	}

	if itemCount > 0 {
		// Finish the last batch
		if err := client.BatchGetItemPages(input, updateResult); err != nil {
			return nil, err
		}
	}

	zap.L().Info("BatchGetItem successful", zap.Duration("duration", time.Since(start)))
	return result, nil
}
