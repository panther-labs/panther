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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
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

func TestUpdateDoestNotExist(t *testing.T) {
	mockClient := &mockDynamoClient{}
	returnErr := awserr.New(dynamodb.ErrCodeConditionalCheckFailedException, "", nil)
	mockClient.On("UpdateItem", mock.Anything).Return(
		(*dynamodb.UpdateItemOutput)(nil), returnErr)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("table-name")}

	result, err := table.Update(&models.Organization{})
	mockClient.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.DoesNotExistError{}, err)
}

func TestUpdateServiceError(t *testing.T) {
	mockClient := &mockDynamoClient{}
	mockClient.On("UpdateItem", mock.Anything).Return(
		(*dynamodb.UpdateItemOutput)(nil), errors.New("service unavailable"))
	table := &OrganizationsTable{client: mockClient, Name: aws.String("table-name")}

	result, err := table.Update(&models.Organization{})
	mockClient.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.AWSError{}, err)
}

func TestUpdateUnmarshalError(t *testing.T) {
	mockClient := &mockDynamoClient{}
	// output has wrong type for one of the fields
	output := &dynamodb.UpdateItemOutput{
		Attributes: DynamoItem{"awsConfig": {SS: aws.StringSlice([]string{"panther", "labs"})}},
	}
	mockClient.On("UpdateItem", mock.Anything).Return(output, nil)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}

	result, err := table.Update(&models.Organization{})
	mockClient.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.InternalError{}, err)
}

func TestUpdate(t *testing.T) {
	mockClient := &mockDynamoClient{}
	org := &models.Organization{}

	output := &dynamodb.UpdateItemOutput{
		Attributes: DynamoItem{"id": {S: aws.String(orgID)}},
	}

	expectedUpdate := expression.
		Set(expression.Name("alertReportFrequency"), expression.Value(org.AlertReportFrequency)).
		Set(expression.Name("awsConfig"), expression.Value(org.AwsConfig)).
		Set(expression.Name("displayName"), expression.Value(org.DisplayName)).
		Set(expression.Name("email"), expression.Value(org.Email)).
		Set(expression.Name("errorReportingConsent"), expression.Value(org.ErrorReportingConsent)).
		Set(expression.Name("phone"), expression.Value(org.Phone))
	expectedCondition := expression.AttributeExists(expression.Name("id"))
	expectedExpression, _ := expression.NewBuilder().WithCondition(expectedCondition).WithUpdate(expectedUpdate).Build()

	expectedUpdateItemInput := &dynamodb.UpdateItemInput{
		ConditionExpression:       expectedExpression.Condition(),
		ExpressionAttributeNames:  expectedExpression.Names(),
		ExpressionAttributeValues: expectedExpression.Values(),
		Key:                       DynamoItem{"id": {S: aws.String(orgID)}},
		ReturnValues:              aws.String("ALL_NEW"),
		TableName:                 aws.String("test-table"),
		UpdateExpression:          expectedExpression.Update(),
	}

	mockClient.On("UpdateItem", expectedUpdateItemInput).Return(output, nil)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}

	result, err := table.Update(org)
	mockClient.AssertExpectations(t)
	require.NoError(t, err)
	expected := &models.Organization{}
	assert.Equal(t, expected, result)
}

func TestAddActions(t *testing.T) {
	mockClient := &mockDynamoClient{}
	output := &dynamodb.UpdateItemOutput{
		Attributes: DynamoItem{"id": {S: aws.String(orgID)}},
	}
	mockClient.On("UpdateItem", mock.Anything).Return(output, nil)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}
	action := models.VisitedOnboardingFlow
	result, err := table.AddActions([]*models.Action{&action})
	mockClient.AssertExpectations(t)
	require.NoError(t, err)
	expected := &models.Organization{}
	assert.Equal(t, expected, result)
}
