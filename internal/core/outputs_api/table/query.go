package table

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
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/genericapi"
)

// GetOutputByName returns an output given it's displayName. If such output doesn't exist, it returns nil.
func (table *OutputsTable) GetOutputByName(displayName *string) (*AlertOutputItem, error) {
	keyCondition := expression.Key("displayName").Equal(expression.Value(displayName))

	queryExpression, err := expression.NewBuilder().
		WithKeyCondition(keyCondition).
		Build()

	if err != nil {
		return nil, &genericapi.InternalError{Message: "failed to build expression " + err.Error()}
	}

	queryInput := &dynamodb.QueryInput{
		TableName:                 table.Name,
		IndexName:                 table.DisplayNameIndex,
		ExpressionAttributeNames:  queryExpression.Names(),
		ExpressionAttributeValues: queryExpression.Values(),
		KeyConditionExpression:    queryExpression.KeyCondition(),
	}

	queryOutput, err := table.client.Query(queryInput)
	if err != nil {
		return nil, &genericapi.InternalError{Message: "failed to query table" + err.Error()}
	}
	if len(queryOutput.Items) == 0 {
		return nil, nil
	}

	if len(queryOutput.Items) > 1 {
		// Normally the displayName should be unique for an org output
		// If that's not the case, log an error but continue with normal code execution
		// to avoid bad customer experience
		zap.L().Error("there are multiple outputs with the same name",
			zap.String("displayName", *displayName))
	}

	item := &AlertOutputItem{}
	err = dynamodbattribute.UnmarshalMap(queryOutput.Items[0], item)
	if err != nil {
		return nil, &genericapi.InternalError{Message: "failed to unmarshal response" + err.Error()}
	}
	return item, nil
}

// GetOutputs returns all the Alert Outputs for one organization
func (table *OutputsTable) GetOutputs() (outputItems []*AlertOutputItem, err error) {
	var scanInput = &dynamodb.ScanInput{
		TableName: table.Name,
	}

	//TODO replace with dynamodb.ScanPages method
	for {
		var scanOutput *dynamodb.ScanOutput
		if scanOutput, err = table.client.Scan(scanInput); err != nil {
			return nil, &genericapi.AWSError{Method: "dynamodb.Scan", Err: err}
		}

		var outputItemsPartial []*AlertOutputItem
		if err = dynamodbattribute.UnmarshalListOfMaps(scanOutput.Items, &outputItemsPartial); err != nil {
			return nil, &genericapi.InternalError{
				Message: "failed to unmarshal dynamo item to an AlertOutputItem: " + err.Error()}
		}

		outputItems = append(outputItems, outputItemsPartial...)

		if scanOutput.LastEvaluatedKey == nil {
			return outputItems, nil
		}

		scanInput.ExclusiveStartKey = scanOutput.LastEvaluatedKey
	}
}

// GetOutput returns the configuration of an alert output
func (table *OutputsTable) GetOutput(outputID *string) (*AlertOutputItem, error) {
	getItemInput := &dynamodb.GetItemInput{
		TableName: table.Name,
		Key: map[string]*dynamodb.AttributeValue{
			"outputId": {
				S: outputID,
			},
		},
	}

	result, err := table.client.GetItem(getItemInput)

	if err != nil {
		return nil, &genericapi.AWSError{Method: "dynamodb.GetItem", Err: err}
	}

	if result.Item == nil {
		return nil, &genericapi.DoesNotExistError{
			Message: "outputId=" + *outputID}
	}

	var outputItem *AlertOutputItem
	if err = dynamodbattribute.UnmarshalMap(result.Item, &outputItem); err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to unmarshal dynamo item to an AlertOutputItem: " + err.Error()}
	}

	return outputItem, nil
}
