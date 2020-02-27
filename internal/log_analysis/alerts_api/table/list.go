package table

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

func (table *AlertsTable) ListByRule(ruleID string, exclusiveStartKey *string, pageSize *int) (
	summaries []*models.AlertItem, lastEvaluatedKey *string, err error) {

	return table.list(RuleIDKey, ruleID, exclusiveStartKey, pageSize)
}

func (table *AlertsTable) ListAll(exclusiveStartKey *string, pageSize *int) (
	summaries []*models.AlertItem, lastEvaluatedKey *string, err error) {

	return table.list(TimePartitionKey, TimePartitionValue, exclusiveStartKey, pageSize)
}

// list returns a page of alerts ordered by creationTime, last evaluated key, any error
func (table *AlertsTable) list(ddbKey, ddbValue string, exclusiveStartKey *string, pageSize *int) (
	summaries []*models.AlertItem, lastEvaluatedKey *string, err error) {

	// pick index
	var index string
	if ddbKey == RuleIDKey {
		index = table.RuleIDCreationTimeIndexName
	} else if ddbKey == TimePartitionKey {
		index = table.TimePartitionCreationTimeIndexName
	} else {
		return nil, nil, errors.New("unknown key" + ddbKey)
	}

	// queries require and = condition on primary key
	keyCondition := expression.Key(ddbKey).Equal(expression.Value(&ddbValue))

	queryExpression, err := expression.NewBuilder().
		WithKeyCondition(keyCondition).
		Build()

	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build expression")
	}

	var queryResultsLimit *int64
	if pageSize != nil {
		queryResultsLimit = aws.Int64(int64(*pageSize))
	}

	var queryExclusiveStartKey map[string]*dynamodb.AttributeValue
	if exclusiveStartKey != nil {
		queryExclusiveStartKey = make(map[string]*dynamodb.AttributeValue)
		err = jsoniter.UnmarshalFromString(*exclusiveStartKey, &queryExclusiveStartKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to Unmarshal ExclusiveStartKey")
		}
	}

	var queryInput = &dynamodb.QueryInput{
		TableName:                 &table.AlertsTableName,
		ScanIndexForward:          aws.Bool(false),
		ExpressionAttributeNames:  queryExpression.Names(),
		ExpressionAttributeValues: queryExpression.Values(),
		KeyConditionExpression:    queryExpression.KeyCondition(),
		ExclusiveStartKey:         queryExclusiveStartKey,
		IndexName:                 aws.String(index),
		Limit:                     queryResultsLimit,
	}

	queryOutput, err := table.Client.Query(queryInput)
	if err != nil {
		// this deserves detailed logging for debugging
		zap.L().Error("Query()", zap.Error(err), zap.Any("input", queryInput), zap.Any("startKey", queryExclusiveStartKey))
		return nil, nil, errors.Wrapf(err, "QueryInput() failed for %s,%s", ddbKey, ddbValue)
	}

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
