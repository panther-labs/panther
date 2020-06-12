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

// getKeyCondition - gets the appropriate key condition for a query
//
// If a `RuleID` is present, then create the KeyCondition based on this field.
// Otherwise, use the default time partition key condition
func (table *AlertsTable) getKeyCondition(input *models.ListAlertsInput) (keyCondition expression.KeyConditionBuilder) {
	if input.RuleID != nil {
		keyCondition = expression.Key(RuleIDKey).Equal(expression.Value(*input.RuleID))
		return keyCondition
	}
	keyCondition = expression.Key(TimePartitionKey).Equal(expression.Value(TimePartitionValue))
	return keyCondition
}

//	// Queries require an 'equal' condition on theprimary key
// keyCondition := expression.Key(ddbKey).Equal(expression.Value(&ddbValue))

// filterBySeverity - filters by a Severity level
func filterBySeverity(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if input.Severity != nil {
		*filter = filter.And(expression.Equal(expression.Name("severity"), expression.Value(*input.Severity)))
	}
}

// filterByRuleID - fiters by a specific RuleID
func filterByRuleID(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if input.RuleID != nil {
		*filter = filter.And(expression.Equal(expression.Name("ruleID"), expression.Value(*input.RuleID)))
	}
}

// filterByNameContains - fiters by a name that contains a string
func filterByNameContains(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	// Because we return to the frontend a `title` which could be comprised of three attributes,
	// we query across those three attributes.
	if input.Contains != nil {
		*filter = filter.And(
			expression.Or(
				expression.Contains(expression.Name("title"), *input.Contains),
				expression.Contains(expression.Name("ruleId"), *input.Contains),
				expression.Contains(expression.Name("ruleDisplayName"), *input.Contains),
			),
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
	}
}

// applyFilters - adds filters onto an expression
func (table *AlertsTable) applyFilters(builder *expression.Builder, input *models.ListAlertsInput) {
	// Start with an empty filter for a known attribute
	filter := expression.AttributeExists(expression.Name("id"))
	// Then, apply our filters
	filterBySeverity(&filter, input)
	filterByRuleID(&filter, input)
	filterByNameContains(&filter, input)
	filterByEventCount(&filter, input)

	// Finally, overwrite the existing condition filter on the builder
	*builder = builder.WithFilter(filter)
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

	// Construct a query expression
	queryExpression, err := builder.Build()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build expression")
	}

	// Optionally limit the returned results to the page size
	var queryResultsLimit *int64
	if input.PageSize != nil {
		queryResultsLimit = aws.Int64(int64(*input.PageSize))
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
	if len(queryOutput.LastEvaluatedKey) > 0 {
		lastEvaluatedKeySerialized, err := jsoniter.MarshalToString(queryOutput.LastEvaluatedKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to Marshal LastEvaluatedKey)")
		}
		lastEvaluatedKey = &lastEvaluatedKeySerialized
	}

	return summaries, lastEvaluatedKey, nil
}
