package table

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
)

// ListByRule - lists all alerts belonging to a specific ruleID
func (table *AlertsTable) ListByRule(input *models.ListAlertsInput) (
	summaries []*AlertItem, lastEvaluatedKey *string, err error) {

	return table.list(RuleIDKey, *input.RuleID, input)
}

// ListAll - lists all alerts (default sort by creation time)
func (table *AlertsTable) ListAll(input *models.ListAlertsInput) (
	summaries []*AlertItem, lastEvaluatedKey *string, err error) {

	return table.list(TimePartitionKey, TimePartitionValue, input)
}

// getIndex - gets the primary index to query
//
// If a `RuleID` is present, then create the index based on this field.
// Otherwise, use the default time partition index
func (table *AlertsTable) getIndex(input *models.ListAlertsInput) (index *string) {
	if input.RuleID != nil {
		index = aws.String(table.RuleIDCreationTimeIndexName)
		return index
	}
	index = aws.String(table.TimePartitionCreationTimeIndexName)
	return index
}

// getKeyBuilder - gets the appropriate key builder
func (table *AlertsTable) getKeyBuilder(input *models.ListAlertsInput) (keyBuilder expression.KeyBuilder) {
	if input.RuleID != nil {
		keyBuilder = expression.Key(RuleIDKey)
		return keyBuilder
	}
	keyBuilder = expression.Key(TimePartitionKey)
	return keyBuilder
}

// getKeyCondition - gets the appropriate key condition for a query
//
// If a `RuleID` is present, then create the KeyCondition based for this field.
// Otherwise, use the default time partition KeyCondition
func (table *AlertsTable) getKeyCondition(keyBuilder *expression.KeyBuilder,
	input *models.ListAlertsInput) (keyCondition expression.KeyConditionBuilder) {

	// If we have a ruleId, set the primary key and allow for filtering by createdAt
	if input.RuleID != nil {
		if input.CreatedAtBefore != nil && input.CreatedAtAfter != nil && input.CreatedAtAfter.After(*input.CreatedAtBefore) {
			keyCondition = keyBuilder.Equal(expression.Value(*input.RuleID)).
				And(
					expression.Key(CreatedAtKey).Between(
						expression.Value(*input.CreatedAtBefore), expression.Value(*input.CreatedAtAfter),
					),
				)
			return keyCondition
		} else if input.CreatedAtAfter != nil && input.CreatedAtBefore == nil {
			keyCondition = keyBuilder.Equal(expression.Value(*input.RuleID)).
				And(
					expression.Key(CreatedAtKey).LessThanEqual(
						expression.Value(*input.CreatedAtAfter),
					),
				)
			return keyCondition
		} else if input.CreatedAtBefore != nil && input.CreatedAtAfter == nil {
			keyCondition = keyBuilder.Equal(expression.Value(*input.RuleID)).
				And(
					expression.Key(CreatedAtKey).GreaterThanEqual(
						expression.Value(*input.CreatedAtBefore),
					),
				)
			return keyCondition
		}

		keyCondition = keyBuilder.Equal(expression.Value(*input.RuleID))
		return keyCondition
	}

	// Otherwise, set the primary key for the time partition and allow for filtering by createdAt
	if input.CreatedAtBefore != nil && input.CreatedAtAfter != nil && input.CreatedAtAfter.After(*input.CreatedAtBefore) {
		keyCondition = keyBuilder.Equal(expression.Value(TimePartitionValue)).
			And(
				expression.Key(CreatedAtKey).Between(
					expression.Value(*input.CreatedAtBefore), expression.Value(*input.CreatedAtAfter),
				),
			)
		return keyCondition
	} else if input.CreatedAtAfter != nil && input.CreatedAtBefore == nil {
		keyCondition = keyBuilder.Equal(expression.Value(TimePartitionValue)).
			And(
				expression.Key(CreatedAtKey).GreaterThanEqual(
					expression.Value(*input.CreatedAtAfter),
				),
			)
		return keyCondition
	} else if input.CreatedAtBefore != nil && input.CreatedAtAfter == nil {
		keyCondition = keyBuilder.Equal(expression.Value(TimePartitionValue)).
			And(
				expression.Key(CreatedAtKey).LessThanEqual(
					expression.Value(*input.CreatedAtBefore),
				),
			)
		return keyCondition
	}

	keyCondition = keyBuilder.Equal(expression.Value(TimePartitionValue))
	return keyCondition
}

// filterBySeverity - filters by a Severity level
func filterBySeverity(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if input.Severity != nil {
		*filter = filter.And(
			expression.Equal(expression.Name("severity"), expression.Value(*input.Severity)),
		)
	}
}

// filterByTitleContains - fiters by a name that contains a string (case sensitive)
func filterByTitleContains(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if input.Contains != nil {
		*filter = filter.And(
			expression.Contains(expression.Name("title"), *input.Contains),
		)
	}
}

// filterByEventCount - fiters by an eventCount defined by a range of two numbers
func filterByEventCount(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	// Ensure we are checking for valid inputs that are within an acceptable range
	if input.EventCountMax != nil && input.EventCountMin != nil && *input.EventCountMin >= 0 && *input.EventCountMax >= *input.EventCountMin {
		*filter = filter.And(
			expression.GreaterThanEqual(expression.Name("eventCount"), expression.Value(*input.EventCountMin)),
			expression.LessThanEqual(expression.Name("eventCount"), expression.Value(*input.EventCountMax)),
		)
	} else if input.EventCountMax != nil && input.EventCountMin == nil && *input.EventCountMax >= 0 {
		*filter = filter.And(
			expression.LessThanEqual(expression.Name("eventCount"), expression.Value(*input.EventCountMax)),
		)
	} else if input.EventCountMin != nil && input.EventCountMax == nil && *input.EventCountMin >= 0 {
		*filter = filter.And(
			expression.GreaterThanEqual(expression.Name("eventCount"), expression.Value(*input.EventCountMin)),
		)
	}
}

// applyFilters - adds filters onto an expression
func (table *AlertsTable) applyFilters(builder *expression.Builder, input *models.ListAlertsInput) {
	// Start with an empty filter for a known attribute
	filter := expression.AttributeExists(expression.Name("id"))

	// Then, apply our filters
	filterBySeverity(&filter, input)
	filterByTitleContains(&filter, input)
	filterByEventCount(&filter, input)

	// Finally, overwrite the existing condition filter on the builder
	*builder = builder.WithFilter(filter)
}

// list - returns a page of alerts ordered by creationTime, last evaluated key, any error
func (table *AlertsTable) list(ddbKey, ddbValue string, input *models.ListAlertsInput) (
	summaries []*AlertItem, lastEvaluatedKey *string, err error) {

	// Get the primary key index to query by
	index := table.getIndex(input)

	// Get the key builder for the query
	keyBuilder := table.getKeyBuilder(input)

	// Get the key condition for the query
	keyCondition := table.getKeyCondition(&keyBuilder, input)

	// Construct a new builder instance with the above index as our key condition
	builder := expression.NewBuilder().WithKeyCondition(keyCondition)

	// Apply the all applicable filters specified by the input
	table.applyFilters(&builder, input)

	// Construct a query expression
	queryExpression, err := builder.Build()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build expression")
	}

	// Limit the returned results to the specified page size or max default
	var queryResultsLimit *int64
	if input.PageSize != nil {
		queryResultsLimit = aws.Int64(int64(*input.PageSize))
	} else {
		queryResultsLimit = aws.Int64(int64(25))
	}

	// Optionally continue the query from the "primary key of the item where the [previous] operation stopped"
	var queryExclusiveStartKey map[string]*dynamodb.AttributeValue
	if input.ExclusiveStartKey != nil {
		queryExclusiveStartKey = make(map[string]*dynamodb.AttributeValue)
		err = jsoniter.UnmarshalFromString(*input.ExclusiveStartKey, &queryExclusiveStartKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to Unmarshal ExclusiveStartKey")
		}
	}

	// Construct the full query
	var queryInput = &dynamodb.QueryInput{
		TableName:                 &table.AlertsTableName,
		ScanIndexForward:          aws.Bool(false),
		ExpressionAttributeNames:  queryExpression.Names(),
		ExpressionAttributeValues: queryExpression.Values(),
		FilterExpression:          queryExpression.Filter(),
		KeyConditionExpression:    queryExpression.KeyCondition(),
		ExclusiveStartKey:         queryExclusiveStartKey,
		IndexName:                 index,
		Limit:                     queryResultsLimit,
	}

	// Get the results of the query
	queryOutput, err := table.Client.Query(queryInput)
	if err != nil {
		// this deserves detailed logging for debugging
		zap.L().Error("Query()", zap.Error(err), zap.Any("input", queryInput), zap.Any("startKey", queryExclusiveStartKey))
		return nil, nil, errors.Wrapf(err, "QueryInput() failed for %s,%s", ddbKey, ddbValue)
	}

	// Unmarshal the raw items unto the `summaries`
	err = dynamodbattribute.UnmarshalListOfMaps(queryOutput.Items, &summaries)
	if err != nil {
		return nil, nil, errors.Wrap(err, "UnmarshalListOfMaps() failed")
	}

	// If DDB returned a LastEvaluatedKey (the "primary key of the item where the operation stopped"),
	// it means there are more alerts to be returned. Return populated `lastEvaluatedKey` JSON blob in the response.
	//
	// NOTE:
	// "A `Query` operation can return an empty result set and a `LastEvaluatedKey` if all the items read for
	// the page of results are filtered out."
	// (https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Query.html)
	if len(queryOutput.LastEvaluatedKey) > 0 {
		lastEvaluatedKeySerialized, err := jsoniter.MarshalToString(queryOutput.LastEvaluatedKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to Marshal LastEvaluatedKey)")
		}
		lastEvaluatedKey = &lastEvaluatedKeySerialized
	}

	return summaries, lastEvaluatedKey, nil
}
