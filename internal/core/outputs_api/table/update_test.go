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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/pkg/genericapi"
)

var mockUpdateItemOutput = &dynamodb.UpdateItemOutput{
	Attributes: map[string]*dynamodb.AttributeValue{
		"outputId": {
			S: aws.String("outputId"),
		},
	},
}
var mockUpdateItemAlertOutput = &AlertOutputItem{
	OutputID:           aws.String("outputId"),
	DisplayName:        aws.String("displayName"),
	LastModifiedBy:     aws.String("lastModifiedBy"),
	LastModifiedTime:   aws.String("lastModifiedTime"),
	OutputType:         aws.String("outputType"),
	DefaultForSeverity: aws.StringSlice([]string{"INFO", "WARN"}),
	AlertTypes:         []string{"RULE", "RULE_ERROR", "POLICY"},
	EncryptedConfig:    make([]byte, 1),
}

func TestUpdateOutput(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient, Name: aws.String("TableName")}

	expectedUpdateExpression := expression.
		Set(expression.Name("lastModifiedBy"), expression.Value(mockUpdateItemAlertOutput.LastModifiedBy)).
		Set(expression.Name("lastModifiedTime"), expression.Value(mockUpdateItemAlertOutput.LastModifiedTime)).
		Set(expression.Name("displayName"), expression.Value(mockUpdateItemAlertOutput.DisplayName)).
		Set(expression.Name("encryptedConfig"), expression.Value(mockUpdateItemAlertOutput.EncryptedConfig)).
		Set(expression.Name("defaultForSeverity"), expression.Value(mockUpdateItemAlertOutput.DefaultForSeverity)).
		Set(expression.Name("alertTypes"), expression.Value(mockUpdateItemAlertOutput.AlertTypes))

	expectedConditionExpression := expression.Name("outputId").Equal(expression.Value(mockUpdateItemAlertOutput.OutputID))

	expectedExpression, _ := expression.NewBuilder().
		WithCondition(expectedConditionExpression).
		WithUpdate(expectedUpdateExpression).
		Build()

	expectedUpdateItemInput := &dynamodb.UpdateItemInput{
		Key: DynamoItem{
			"outputId": {S: aws.String("outputId")},
		},
		TableName:                 aws.String("TableName"),
		UpdateExpression:          expectedExpression.Update(),
		ConditionExpression:       expectedExpression.Condition(),
		ExpressionAttributeNames:  expectedExpression.Names(),
		ExpressionAttributeValues: expectedExpression.Values(),
		ReturnValues:              aws.String(dynamodb.ReturnValueAllNew),
	}
	expectedResult := &AlertOutputItem{
		OutputID: aws.String("outputId"),
	}

	dynamoDBClient.On("UpdateItem", expectedUpdateItemInput).Return(mockUpdateItemOutput, nil)
	result, err := table.UpdateOutput(mockUpdateItemAlertOutput)
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	dynamoDBClient.AssertExpectations(t)
}

func TestUpdateOutputDoesNotExist(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient, Name: aws.String("TableName")}

	dynamoDBClient.On("UpdateItem", mock.Anything).Return(
		mockUpdateItemOutput,
		awserr.New(dynamodb.ErrCodeConditionalCheckFailedException, "attribute does not exist", nil))

	result, error := table.UpdateOutput(mockUpdateItemAlertOutput)
	assert.Nil(t, result)
	assert.Error(t, error)
	assert.NotNil(t, error.(*genericapi.DoesNotExistError))
	dynamoDBClient.AssertExpectations(t)
}

func TestUpdateOutputServiceError(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient, Name: aws.String("TableName")}

	dynamoDBClient.On("UpdateItem", mock.Anything).Return(
		mockUpdateItemOutput,
		awserr.New(dynamodb.ErrCodeResourceNotFoundException, "table does not exist", nil))

	result, err := table.UpdateOutput(mockUpdateItemAlertOutput)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.NotNil(t, err.(*genericapi.AWSError))
	dynamoDBClient.AssertExpectations(t)
}

func TestUpdateMarshallingError(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient, Name: aws.String("TableName")}
	mockUpdateItemOutput.Attributes["outputId"] = &dynamodb.AttributeValue{BOOL: aws.Bool(false)}

	dynamoDBClient.On("UpdateItem", mock.Anything).Return(mockUpdateItemOutput, nil)

	result, err := table.UpdateOutput(mockUpdateItemAlertOutput)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.NotNil(t, err.(*genericapi.InternalError))
	dynamoDBClient.AssertExpectations(t)
}
