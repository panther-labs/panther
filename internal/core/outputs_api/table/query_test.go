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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var mockItemMap = map[string]*dynamodb.AttributeValue{
	"outputId": {
		S: aws.String("outputId"),
	},
}

var mockScanItemOutput = &dynamodb.ScanOutput{
	Count: aws.Int64(1),
	Items: []map[string]*dynamodb.AttributeValue{mockItemMap},
}

func TestGetOutputByNameOutputNotFound(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient, Name: aws.String("testTable"), DisplayNameIndex: aws.String("displayIndex")}
	expectedKeyCondition := expression.Key("displayName").Equal(expression.Value(aws.String("displayName")))
	expectedQueryExpression, _ := expression.NewBuilder().
		WithKeyCondition(expectedKeyCondition).
		Build()
	expectedQueryInput := &dynamodb.QueryInput{
		TableName:                 aws.String("testTable"),
		IndexName:                 aws.String("displayIndex"),
		ExpressionAttributeNames:  expectedQueryExpression.Names(),
		ExpressionAttributeValues: expectedQueryExpression.Values(),
		KeyConditionExpression:    expectedQueryExpression.KeyCondition(),
	}
	dynamoResponse := &dynamodb.QueryOutput{Items: make([]map[string]*dynamodb.AttributeValue, 0)}
	dynamoDBClient.On("Query", expectedQueryInput).Return(dynamoResponse, nil)

	result, err := table.GetOutputByName(aws.String("displayName"))
	assert.Nil(t, result)
	assert.NoError(t, err)
	dynamoDBClient.AssertExpectations(t)
}

func TestGetOutputByName(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient}

	dynamoResponse := &dynamodb.QueryOutput{Items: make([]map[string]*dynamodb.AttributeValue, 1)}
	dynamoDBClient.On("Query", mock.Anything).Return(dynamoResponse, nil)

	result, err := table.GetOutputByName(aws.String("displayName"))

	assert.NotNil(t, result)
	assert.NoError(t, err)
	dynamoDBClient.AssertExpectations(t)
}

func TestCheckDuplicateNameServiceError(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient}

	dynamoDBClient.On("Query", mock.Anything).Return(&dynamodb.QueryOutput{}, errors.New("failed"))

	result, err := table.GetOutputByName(aws.String("displayName"))

	require.Nil(t, result)
	assert.Error(t, err)
	dynamoDBClient.AssertExpectations(t)
}

func TestGetOutputs(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient, Name: aws.String("testTable")}
	expectedScanExpression, _ := expression.NewBuilder().Build()
	expectedScanInput := &dynamodb.ScanInput{
		TableName:                 aws.String("testTable"),
		ExpressionAttributeNames:  expectedScanExpression.Names(),
		ExpressionAttributeValues: expectedScanExpression.Values(),
	}

	dynamoDBClient.On("Scan", expectedScanInput).Return(mockScanItemOutput, nil)
	expectedResult := &AlertOutputItem{
		OutputID: aws.String("outputId"),
	}

	result, err := table.GetOutputs()
	require.NoError(t, err)
	assert.Equal(t, []*AlertOutputItem{expectedResult}, result)

	dynamoDBClient.AssertExpectations(t)
}

func TestGetOutputsPagination(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{client: dynamoDBClient}

	dynamoResponseInitial := &dynamodb.ScanOutput{Items: []map[string]*dynamodb.AttributeValue{mockItemMap}, LastEvaluatedKey: mockItemMap}
	dynamoResponseFinal := &dynamodb.ScanOutput{Items: []map[string]*dynamodb.AttributeValue{mockItemMap}, LastEvaluatedKey: nil}

	// Returning a response that contains "LastEvaluatedKey" should force the application to re-submit query
	dynamoDBClient.On("Scan", mock.Anything).Return(dynamoResponseInitial, nil).Twice()
	dynamoDBClient.On("Scan", mock.Anything).Return(dynamoResponseFinal, nil)

	expectedResult := &AlertOutputItem{
		OutputID: aws.String("outputId"),
	}

	result, err := table.GetOutputs()

	require.NoError(t, err)
	assert.Equal(t, []*AlertOutputItem{expectedResult, expectedResult, expectedResult}, result)
	dynamoDBClient.AssertExpectations(t)
}

func TestGetOutput(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{
		client: dynamoDBClient,
		Name:   aws.String("testTable"),
	}

	expectedGetItemInput := &dynamodb.GetItemInput{
		TableName: aws.String("testTable"),
		Key: map[string]*dynamodb.AttributeValue{
			"outputId": {
				S: aws.String("outputId"),
			},
		},
	}
	mockGetItemOutput := &dynamodb.GetItemOutput{Item: mockItemMap}
	dynamoDBClient.On("GetItem", expectedGetItemInput).Return(mockGetItemOutput, nil)

	expectedResult := &AlertOutputItem{
		OutputID: aws.String("outputId"),
	}

	result, err := table.GetOutput(aws.String("outputId"))
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	dynamoDBClient.AssertExpectations(t)
}

func TestGetOutputNoResult(t *testing.T) {
	dynamoDBClient := &mockDynamoDB{}
	table := &OutputsTable{
		client: dynamoDBClient,
		Name:   aws.String("testTable"),
	}

	dynamoDBClient.On("GetItem", mock.Anything).Return(&dynamodb.GetItemOutput{}, nil)

	result, err := table.GetOutput(aws.String("outputId"))
	require.Nil(t, result)
	assert.Error(t, err)
	dynamoDBClient.AssertExpectations(t)
}
