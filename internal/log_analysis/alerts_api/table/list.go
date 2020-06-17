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

// ListAll - lists all alerts and apply filtering, sorting logic
func (table *AlertsTable) ListAll(input *models.ListAlertsInput) (
	summaries []*AlertItem, lastEvaluatedKey *string, err error) {

	return table.list(TimePartitionKey, TimePartitionValue, input)
}

// list - returns a page of alerts ordered by creationTime, last evaluated key, any error
func (table *AlertsTable) list(ddbKey, ddbValue string, input *models.ListAlertsInput) (
	summaries []*AlertItem, lastEvaluatedKey *string, err error) {

	// Get the primary key index to query by
	index := table.getIndex(input)

	// Get the key condition for the query
	keyCondition := table.getKeyCondition(input)

	// Construct a new builder instance with the above index as our key condition
	builder := expression.NewBuilder().WithKeyCondition(keyCondition)

	// Apply the all applicable filters specified by the input
	table.applyFilters(&builder, input)

	// Get the sort direction
	direction := table.isAscendingOrder(input)

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
		ScanIndexForward:          aws.Bool(direction),
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

// getIndex - gets the primary index to query
func (table *AlertsTable) getIndex(input *models.ListAlertsInput) *string {
	if input.RuleID != nil {
		return aws.String(table.RuleIDCreationTimeIndexName)
	}
	return aws.String(table.TimePartitionCreationTimeIndexName)
}

// getKeyCondition - gets the key condition for a query
func (table *AlertsTable) getKeyCondition(input *models.ListAlertsInput) expression.KeyConditionBuilder {
	var keyCondition expression.KeyConditionBuilder

	// Define the primary key to use.
	if input.RuleID != nil {
		keyCondition = expression.Key(RuleIDKey).Equal(expression.Value(*input.RuleID))
	} else {
		keyCondition = expression.Key(TimePartitionKey).Equal(expression.Value(TimePartitionValue))
	}

	// Unless we create a custom validator, this is the way we will allow for conditionals
	// We are allowing either Before -or- After to work together or independently
	if input.CreatedAtAfter != nil && input.CreatedAtBefore != nil && input.CreatedAtBefore.After(*input.CreatedAtAfter) {
		keyCondition = keyCondition.And(
			expression.Key(CreatedAtKey).Between(
				expression.Value(*input.CreatedAtAfter),
				expression.Value(*input.CreatedAtBefore),
			),
		)
	}
	if input.CreatedAtAfter != nil && input.CreatedAtBefore == nil {
		keyCondition = keyCondition.And(
			expression.Key(CreatedAtKey).GreaterThanEqual(expression.Value(*input.CreatedAtAfter)))
	}
	if input.CreatedAtAfter == nil && input.CreatedAtBefore != nil {
		keyCondition = keyCondition.And(
			expression.Key(CreatedAtKey).LessThanEqual(expression.Value(*input.CreatedAtBefore)))
	}

	return keyCondition
}

// applyFilters - adds filters onto an expression
func (table *AlertsTable) applyFilters(builder *expression.Builder, input *models.ListAlertsInput) {
	// Start with an empty filter for a known attribute
	filter := expression.AttributeExists(expression.Name(AlertIDKey))

	// Then, apply our filters
	filterBySeverity(&filter, input)
	filterByTitleContains(&filter, input)
	filterByEventCount(&filter, input)

	// Finally, overwrite the existing condition filter on the builder
	*builder = builder.WithFilter(filter)
}

// filterBySeverity - filters by a Severity level
func filterBySeverity(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if input.Severity != nil {
		*filter = filter.And(
			expression.Equal(expression.Name(Severity), expression.Value(*input.Severity)),
		)
	}
}

// filterByTitleContains - fiters by a name that contains a string (case sensitive)
func filterByTitleContains(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if input.NameContains != nil {
		*filter = filter.And(
			expression.Contains(expression.Name(Title), *input.NameContains),
		)
	}
}

// filterByEventCount - fiters by an eventCount defined by a range of two numbers
func filterByEventCount(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	// Unless we create a custom validator, this is the way we will allow for conditionals
	// We are allowing either Min -or- Max to work together or independently
	if input.EventCountMax != nil && input.EventCountMin != nil && *input.EventCountMax >= *input.EventCountMin {
		*filter = filter.And(
			expression.LessThanEqual(expression.Name(EventCount), expression.Value(*input.EventCountMax)),
			expression.GreaterThanEqual(expression.Name(EventCount), expression.Value(*input.EventCountMin)),
		)
	}
	if input.EventCountMax != nil && input.EventCountMin == nil {
		*filter = filter.And(expression.LessThanEqual(expression.Name(EventCount), expression.Value(*input.EventCountMax)))
	}
	if input.EventCountMax == nil && input.EventCountMin != nil {
		*filter = filter.And(expression.GreaterThanEqual(expression.Name(EventCount), expression.Value(*input.EventCountMin)))
	}
}

// isAscendingOrder - determines which direction to sort the data
func (table *AlertsTable) isAscendingOrder(input *models.ListAlertsInput) bool {
	// By default, sort descending
	if input.SortDir == nil {
		return false
	}
	return *input.SortDir == "ascending"
}
