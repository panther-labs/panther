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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/genericapi"
)

func (m *mockDynamoClient) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}

func TestGetItemAwsError(t *testing.T) {
	mockClient := &mockDynamoClient{}
	mockClient.On("GetItem", mock.Anything).Return(
		(*dynamodb.GetItemOutput)(nil), errors.New("service unavailable"))
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}

	result, err := table.GetGeneralSettings()
	mockClient.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.AWSError{}, err)
}

func TestGetItemUnmarshalError(t *testing.T) {
	mockClient := &mockDynamoClient{}
	// output has wrong type for one of the fields
	output := &dynamodb.GetItemOutput{
		Item: DynamoItem{
			"email": {SS: aws.StringSlice([]string{"panther", "labs"})},
		},
	}
	mockClient.On("GetItem", mock.Anything).Return(output, nil)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}

	result, err := table.GetGeneralSettings()
	mockClient.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.InternalError{}, err)
}

func TestGetItem(t *testing.T) {
	mockClient := &mockDynamoClient{}
	expectedInput := &dynamodb.GetItemInput{
		Key:       settingsKey,
		TableName: aws.String("test-table"),
	}
	output := &dynamodb.GetItemOutput{Item: DynamoItem{
		"id":    {S: aws.String("generalSettings")},
		"email": {S: aws.String("email")},
	}}
	mockClient.On("GetItem", expectedInput).Return(output, nil)
	table := &OrganizationsTable{client: mockClient, Name: aws.String("test-table")}

	_, err := table.GetGeneralSettings()
	mockClient.AssertExpectations(t)
	require.NoError(t, err)
}
