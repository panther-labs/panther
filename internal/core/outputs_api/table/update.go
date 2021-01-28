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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateOutput updates an existing item in the table
func (table *OutputsTable) UpdateOutput(alertOutput *AlertOutputItem) (*AlertOutputItem, error) {
	// These fields will always be sent
	updateExpression := expression.
		Set(expression.Name("lastModifiedBy"), expression.Value(alertOutput.LastModifiedBy)).
		Set(expression.Name("lastModifiedTime"), expression.Value(alertOutput.LastModifiedTime))

	if alertOutput.DisplayName != nil {
		updateExpression.Set(expression.Name("displayName"), expression.Value(alertOutput.DisplayName))
	}
	if alertOutput.EncryptedConfig != nil {
		updateExpression.Set(expression.Name("encryptedConfig"), expression.Value(alertOutput.EncryptedConfig))
	}
	if alertOutput.DefaultForSeverity != nil {
		updateExpression.Set(expression.Name("defaultForSeverity"), expression.Value(alertOutput.DefaultForSeverity))
	}
	if alertOutput.AlertTypes != nil {
		updateExpression.Set(expression.Name("alertTypes"), expression.Value(alertOutput.AlertTypes))
	}

	conditionExpression := expression.Name("outputId").Equal(expression.Value(alertOutput.OutputID))
	combinedExpression, err := expression.NewBuilder().
		WithCondition(conditionExpression).
		WithUpdate(updateExpression).
		Build()

	if err != nil {
		return nil, &genericapi.InternalError{Message: "failed to build expression " + err.Error()}
	}

	updateResult, err := table.client.UpdateItem(
		&dynamodb.UpdateItemInput{
			TableName: table.Name,
			Key: DynamoItem{
				"outputId": {S: alertOutput.OutputID},
			},
			UpdateExpression:          combinedExpression.Update(),
			ConditionExpression:       combinedExpression.Condition(),
			ExpressionAttributeNames:  combinedExpression.Names(),
			ExpressionAttributeValues: combinedExpression.Values(),
			ReturnValues:              aws.String(dynamodb.ReturnValueAllNew),
		})

	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			return nil, &genericapi.DoesNotExistError{Message: "outputId=" + *alertOutput.OutputID}
		}
		return nil, &genericapi.AWSError{Method: "dynamodb.UpdateItem", Err: err}
	}

	var output AlertOutputItem
	if err = dynamodbattribute.UnmarshalMap(updateResult.Attributes, &output); err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to unmarshal dynamo item to an AlertOutputItem: " + err.Error()}
	}
	return &output, nil
}
