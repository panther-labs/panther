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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
)

// ListAll - lists all alerts and apply filtering, sorting logic
func (table *AlertsTable) ListAll(input *models.ListAlertsInput) (
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
	queryExpression, builderError := builder.Build()
	if builderError != nil {
		return nil, nil, errors.Wrap(builderError, "failed to build expression")
	}

	// Limit the returned results to the specified page size or max default
	var queryResultsLimit *int64
	if input.PageSize != nil {
		queryResultsLimit = aws.Int64(int64(*input.PageSize))
	} else {
		queryResultsLimit = aws.Int64(int64(25))
	}

	// Optionally continue the query from the "primary key of the item where the [previous] operation stopped"
	queryExclusiveStartKey, startKeyErr := getExclusiveStartKey(input)
	if startKeyErr != nil {
		return nil, nil, startKeyErr
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
	}

	var lastKey DynamoItem
	var errMarshal error
	// Continuously query until we have enough results for the requested page size
	err = table.Client.QueryPages(queryInput, func(page *dynamodb.QueryOutput, isLast bool) bool {
		for _, item := range page.Items {
			// Define temp container
			var alert *AlertItem
			// Unmarshal each item to an alert
			if err = dynamodbattribute.UnmarshalMap(item, &alert); err != nil {
				// Something is wrong with this Dynamo item
				errMarshal = err
				return false
			}

			// Perform post-filtering data returned from ddb
			alert = filterByTitleContains(input, alert)

			if alert != nil {
				summaries = append(summaries, alert)
			}

			// If we've reached the page size defined by (default 25)
			if int64(len(summaries)) == *queryResultsLimit {
				lastKey = getLastKey(input, item)
				return false // we are done, stop paging
			}
		}
		return true // keep paging
	})

	// Check for any errors from the query or unmarshaling
	if err != nil || errMarshal != nil {
		var reportErr error
		if err != nil {
			reportErr = err
		} else {
			reportErr = errMarshal
		}
		// this deserves detailed logging for debugging
		zap.L().Error("QueryPages()", zap.Error(reportErr), zap.Any("input", queryInput), zap.Any("startKey", queryExclusiveStartKey))
		if input.RuleID != nil {
			return nil, nil, errors.Wrapf(reportErr, "QueryPages() failed for %s,%s", RuleIDKey, *input.RuleID)
		}
		return nil, nil, errors.Wrapf(reportErr, "QueryPages() failed for %s,%s", TimePartitionKey, TimePartitionValue)
	}

	// If DDB returned a LastEvaluatedKey (the "primary key of the item where the operation stopped"),
	// it means there are more alerts to be returned. Return populated `lastEvaluatedKey` JSON blob in the response.
	//
	// "A `Query` operation can return an empty result set and a `LastEvaluatedKey` if all the items read for
	// the page of results are filtered out."
	// (https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Query.html)
	if len(lastKey) > 0 {
		lastEvaluatedKeySerialized, err := jsoniter.MarshalToString(lastKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to Marshal LastEvaluatedKey)")
		}
		lastEvaluatedKey = &lastEvaluatedKeySerialized
	}

	return summaries, lastEvaluatedKey, nil
}

// getExclusiveStartKey - if the input request contains a key, unmarshal it to use
func getExclusiveStartKey(input *models.ListAlertsInput) (DynamoItem, error) {
	var queryExclusiveStartKey DynamoItem
	if input.ExclusiveStartKey != nil {
		queryExclusiveStartKey = make(DynamoItem)
		err := jsoniter.UnmarshalFromString(*input.ExclusiveStartKey, &queryExclusiveStartKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to Unmarshal ExclusiveStartKey")
		}
	}
	return queryExclusiveStartKey, nil
}

// getLastKey - manually constructs the lastEvaluatedKey to be returned to the frontend
func getLastKey(input *models.ListAlertsInput, item DynamoItem) DynamoItem {
	// There are two types of queries, one from the list alerts page (by time partition)
	// and the other when listing alerts by viewing the rule details (by rule id)
	if input.RuleID != nil {
		return DynamoItem{
			RuleIDKey:    item[RuleIDKey],
			CreatedAtKey: item[CreatedAtKey],
			AlertIDKey:   item[AlertIDKey],
		}
	}
	return DynamoItem{
		TimePartitionKey: item[TimePartitionKey],
		CreatedAtKey:     item[CreatedAtKey],
		AlertIDKey:       item[AlertIDKey],
	}
}

// getIndex - gets the primary index to query
func (table *AlertsTable) getIndex(input *models.ListAlertsInput) *string {
	if input.RuleID != nil {
		return &table.RuleIDCreationTimeIndexName
	}
	return &table.TimePartitionCreationTimeIndexName
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

	// We are allowing either Before -or- After to work together or independently
	switch {
	case input.CreatedAtAfter != nil && input.CreatedAtBefore != nil:
		keyCondition = keyCondition.And(
			expression.Key(CreatedAtKey).Between(
				expression.Value(*input.CreatedAtAfter),
				expression.Value(*input.CreatedAtBefore),
			),
		)
	case input.CreatedAtAfter != nil && input.CreatedAtBefore == nil:
		keyCondition = keyCondition.And(
			expression.Key(CreatedAtKey).GreaterThanEqual(expression.Value(*input.CreatedAtAfter)))
	case input.CreatedAtAfter == nil && input.CreatedAtBefore != nil:
		keyCondition = keyCondition.And(
			expression.Key(CreatedAtKey).LessThanEqual(expression.Value(*input.CreatedAtBefore)))
	}

	return keyCondition
}

// applyFilters - adds filters onto an expression
func (table *AlertsTable) applyFilters(builder *expression.Builder, input *models.ListAlertsInput) {
	// Start with an empty filter for a known attribute
	filter := expression.AttributeExists(expression.Name(AlertIDKey))

	// TODO: It would read better if each of the below methods returned the multifilter and this block of code would `And` the filters
	// See https://github.com/panther-labs/panther/pull/1790#discussion_r508342774
	//
	// Then, apply our filters
	filterBySeverity(&filter, input)
	filterByStatus(&filter, input)
	filterByEventCount(&filter, input)
	filterByLogType(&filter, input)
	filterByResourceType(&filter, input)
	filterByType(&filter, input)

	// Finally, overwrite the existing condition filter on the builder
	*builder = builder.WithFilter(filter)
}

// filterBySeverity - filters by Severity level(s)
func filterBySeverity(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if len(input.Severity) > 0 {
		// Start with the first known key
		multiFilter := expression.Name(SeverityKey).Equal(expression.Value(input.Severity[0]))

		// Then add or conditions starting at a new slice from the second index
		for _, severityLevel := range input.Severity[1:] {
			multiFilter = multiFilter.Or(expression.Name(SeverityKey).Equal(expression.Value(severityLevel)))
		}

		*filter = filter.And(multiFilter)
	}
}

// filterByStatus - filters by Status(es)
func filterByStatus(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if len(input.Status) > 0 {
		// Start with the first known key
		var multiFilter expression.ConditionBuilder

		// Alerts that don't have a status or have an empty string status are considered open.
		if input.Status[0] == models.OpenStatus {
			multiFilter = expression.
				Or(
					expression.AttributeNotExists(expression.Name(StatusKey)),
					expression.Equal(expression.Name(StatusKey), expression.Value("")),
				)
		} else {
			multiFilter = expression.Name(StatusKey).Equal(expression.Value(input.Status[0]))
		}

		// Then add or conditions starting at a new slice from the second index
		for _, statusSetting := range input.Status[1:] {
			// Alerts that don't have a status or have an empty string status are considered open.
			if statusSetting == models.OpenStatus {
				multiFilter = multiFilter.
					Or(
						expression.AttributeNotExists(expression.Name(StatusKey)),
						expression.Equal(expression.Name(StatusKey), expression.Value("")),
					)
			} else {
				multiFilter = multiFilter.Or(expression.Name(StatusKey).Equal(expression.Value(statusSetting)))
			}
		}

		*filter = filter.And(multiFilter)
	}
}

// filterByLogType - filters by list of log types
func filterByLogType(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if len(input.LogTypes) > 0 {
		// Start with the first known key
		multiFilter := expression.Name(LogTypesKey).Contains(input.LogTypes[0])

		// Then add or conditions starting at a new slice from the second index
		for _, logType := range input.LogTypes[1:] {
			multiFilter = multiFilter.Or(expression.Name(LogTypesKey).Contains(logType))
		}

		*filter = filter.And(multiFilter)
	}
}

// filterByResourceType - filters by list of resource types
func filterByResourceType(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if len(input.ResourceTypes) > 0 {
		// Start with the first known key
		multiFilter := expression.Name(ResourceTypesKey).Contains(input.ResourceTypes[0])

		// Then add or conditions starting at a new slice from the second index
		for _, resourceType := range input.ResourceTypes[1:] {
			multiFilter = multiFilter.Or(expression.Name(ResourceTypesKey).Contains(resourceType))
		}

		*filter = filter.And(multiFilter)
	}
}

// filterByType - filters by the type of the alert
func filterByType(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	if len(input.Types) > 0 {
		// Start with the first known key
		var multiFilter expression.ConditionBuilder

		// Rule errors don't always have the attribute specified for backwards compatibility
		if input.Types[0] == deliverymodel.RuleErrorType {
			multiFilter = expression.
				Or(
					expression.AttributeNotExists(expression.Name(TypeKey)),
					expression.Equal(expression.Name(TypeKey), expression.Value(input.Types[0])),
				)
		} else {
			multiFilter = expression.Name(TypeKey).Equal(expression.Value(input.Types[0]))
		}

		// Then add or conditions starting at a new slice from the second index
		for _, alertType := range input.Types[1:] {
			// Rule errors don't always have the attribute specified for backwards compatibility
			if alertType == deliverymodel.RuleErrorType {
				multiFilter = multiFilter.
					Or(
						expression.AttributeNotExists(expression.Name(TypeKey)),
						expression.Equal(expression.Name(TypeKey), expression.Value(alertType)),
					)
			} else {
				multiFilter = multiFilter.Or(expression.Name(TypeKey).Equal(expression.Value(alertType)))
			}
		}

		*filter = filter.And(multiFilter)
	}
}

// filterByTitleContains - filters alerts by a name that contains a string (case insensitive) against multiple fields
func filterByTitleContains(input *models.ListAlertsInput, alert *AlertItem) *AlertItem {
	// If we don't have a search string, return the alert
	if input.NameContains == nil {
		return alert
	}

	lowerNameContains := strings.ToLower(*input.NameContains)

	// Common across all alert types, we see if it matches an alert title
	if alert.Title != "" && strings.Contains(
		strings.ToLower(alert.Title),
		lowerNameContains,
	) {

		return alert
	}

	// Check for non-policy types in this order: RuleDisplayName, RuleID
	if alert.Type != deliverymodel.PolicyType {
		if alert.RuleDisplayName != nil && strings.Contains(
			strings.ToLower(*alert.RuleDisplayName),
			lowerNameContains,
		) {

			return alert
		}

		if strings.Contains(
			strings.ToLower(alert.RuleID),
			lowerNameContains,
		) {

			return alert
		}
		return nil
	}
	// Check for policy types in this order: ResourceID, PolicyDisplayName, PolicyID
	if strings.Contains(
		strings.ToLower(alert.ResourceID),
		lowerNameContains,
	) {

		return alert
	}

	if strings.Contains(
		strings.ToLower(alert.PolicyDisplayName),
		lowerNameContains,
	) {

		return alert
	}

	if strings.Contains(
		strings.ToLower(alert.PolicyID),
		lowerNameContains,
	) {

		return alert
	}
	return nil
}

// filterByEventCount - filters by an eventCount defined by a range of two numbers
func filterByEventCount(filter *expression.ConditionBuilder, input *models.ListAlertsInput) {
	// We are allowing either Min -or- Max to work together or independently
	if input.EventCountMax != nil && input.EventCountMin != nil {
		*filter = filter.And(
			expression.LessThanEqual(expression.Name(EventCountKey), expression.Value(*input.EventCountMax)),
			expression.GreaterThanEqual(expression.Name(EventCountKey), expression.Value(*input.EventCountMin)),
		)
	}
	if input.EventCountMax != nil && input.EventCountMin == nil {
		*filter = filter.And(expression.LessThanEqual(expression.Name(EventCountKey), expression.Value(*input.EventCountMax)))
	}
	if input.EventCountMax == nil && input.EventCountMin != nil {
		*filter = filter.And(expression.GreaterThanEqual(expression.Name(EventCountKey), expression.Value(*input.EventCountMin)))
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
