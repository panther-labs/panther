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
