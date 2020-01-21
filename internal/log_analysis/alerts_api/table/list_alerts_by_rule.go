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
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ListAlertsByRule returns (a page of alerts, last evaluated key, any error)
func (table *AlertsTable) ListAlertsByRule(ruleID *string, exclusiveStartKey *string, pageSize *int) (
	summaries []*models.AlertItem, lastEvaluatedKey *string, err error) {

	keyCondition := expression.Key("ruleId").Equal(expression.Value(ruleID))

	queryExpression, err := expression.NewBuilder().
		WithKeyCondition(keyCondition).
		Build()

	if err != nil {
		errMsg := "failed to build expression " + err.Error()
		err = errors.WithStack(&genericapi.InternalError{Message: errMsg})
		zap.L().Error(errMsg, zap.Error(err))
		return nil, nil, err
	}

	var queryResultsLimit *int64
	if pageSize != nil {
		queryResultsLimit = aws.Int64(int64(*pageSize))
	}

	var queryExclusiveStartKey map[string]*dynamodb.AttributeValue
	if exclusiveStartKey != nil {
		key := &listAlertsPaginationKey{}
		err = jsoniter.UnmarshalFromString(*exclusiveStartKey, key)
		if err != nil {
			return nil, nil, err
		}
		queryExclusiveStartKey = map[string]*dynamodb.AttributeValue{
			"alertId": {S: key.AlertID},
		}
	}

	var queryInput = &dynamodb.QueryInput{
		TableName:                 &table.AlertsTableName,
		ScanIndexForward:          aws.Bool(false),
		ExpressionAttributeNames:  queryExpression.Names(),
		ExpressionAttributeValues: queryExpression.Values(),
		KeyConditionExpression:    queryExpression.KeyCondition(),
		ExclusiveStartKey:         queryExclusiveStartKey,
		IndexName:                 aws.String(table.RuleIDCreationTimeIndexName),
		Limit:                     queryResultsLimit,
	}

	queryOutput, err := table.Client.Query(queryInput)
	if err != nil {
		errMsg := "query to DDB failed" + err.Error()
		err = errors.WithStack(&genericapi.InternalError{
			Message: errMsg,
		})
		zap.L().Error(errMsg, zap.Error(err))
		return nil, nil, err
	}

	err = dynamodbattribute.UnmarshalListOfMaps(queryOutput.Items, &summaries)
	if err != nil {
		errMsg := "failed to marshall response" + err.Error()
		err = errors.WithStack(&genericapi.InternalError{
			Message: errMsg,
		})
		zap.L().Error(errMsg, zap.Error(err))
		return nil, nil, err
	}

	// If DDB returned a LastEvaluatedKey (the "primary key of the item where the operation stopped"),
	// it means there are more alerts to be returned. Return populated `lastEvaluatedKey` in the response.
	if len(queryOutput.LastEvaluatedKey) > 0 {
		paginationKey := listAlertsPaginationKey{
			AlertID: queryOutput.LastEvaluatedKey["alertId"].S,
		}
		marshalledKey, err := jsoniter.MarshalToString(paginationKey)
		if err != nil {
			errMsg := "failed to marshall key" + err.Error()
			err = errors.WithStack(&genericapi.InternalError{
				Message: errMsg,
			})
			zap.L().Error(errMsg, zap.Error(err))
			return nil, nil, err
		}
		lastEvaluatedKey = &marshalledKey
	}

	return summaries, lastEvaluatedKey, nil
}
