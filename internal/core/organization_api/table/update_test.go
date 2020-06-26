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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

func (m *mockDynamoClient) UpdateItem(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.UpdateItemOutput), args.Error(1)
}

func TestUpdateServiceError(t *testing.T) {
	mockClient := &mockDynamoClient{}
	mockClient.On("UpdateItem", mock.Anything).Return(
		(*dynamodb.UpdateItemOutput)(nil), errors.New("service unavailable"))
	table := &OrganizationsTable{client: mockClient, Name: aws.String("table-name")}

	result, err := table.UpdateGeneralSettings(&models.GeneralSettings{DisplayName: aws.String("panther-test")})
	mockClient.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.AWSError{}, err)
}

func TestUpdateUnmarshalError(t *testing.T) {
	mockClient := &mockDynamoClient{}
	// output has wrong type for one of the fields
	output := &dynamodb.UpdateItemOutput{
		Attributes: DynamoItem{"email": {SS: aws.StringSlice([]string{"panther", "labs"})}},
	}
	mockClient.On("UpdateItem", mock.Anything).Return(output, nil)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}

	result, err := table.UpdateGeneralSettings(&models.GeneralSettings{DisplayName: aws.String("panther-test")})
	mockClient.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.InternalError{}, err)
}

func TestUpdate(t *testing.T) {
	mockClient := &mockDynamoClient{}
	newSettings := &models.GeneralSettings{
		DisplayName: aws.String("panther-test"),
		Email:       aws.String("test@example.com"),
	}

	output := &dynamodb.UpdateItemOutput{Attributes: settingsKey}

	expectedUpdate := expression.
		Remove(expression.Name("noSuchName")).
		Set(expression.Name("displayName"), expression.Value(newSettings.DisplayName)).
		Set(expression.Name("email"), expression.Value(newSettings.Email))
	expectedExpression, _ := expression.NewBuilder().WithUpdate(expectedUpdate).Build()

	expectedUpdateItemInput := &dynamodb.UpdateItemInput{
		ExpressionAttributeNames:  expectedExpression.Names(),
		ExpressionAttributeValues: expectedExpression.Values(),
		Key:                       settingsKey,
		ReturnValues:              aws.String("ALL_NEW"),
		TableName:                 aws.String("test-table"),
		UpdateExpression:          expectedExpression.Update(),
	}

	mockClient.On("UpdateItem", expectedUpdateItemInput).Return(output, nil)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}

	result, err := table.UpdateGeneralSettings(newSettings)
	mockClient.AssertExpectations(t)
	require.NoError(t, err)
	expected := &models.GeneralSettings{}
	assert.Equal(t, expected, result)
}
