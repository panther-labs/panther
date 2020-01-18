package users

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/pkg/genericapi"
)

func (m *mockDynamoClient) DeleteItem(input *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.DeleteItemOutput), args.Error(1)
}

func TestDeleteDoesNotExist(t *testing.T) {
	mockClient := &mockDynamoClient{}
	returnErr := awserr.New(dynamodb.ErrCodeConditionalCheckFailedException, "", nil)
	mockClient.On("DeleteItem", mock.Anything).Return(
		(*dynamodb.DeleteItemOutput)(nil), returnErr)
	table := &Table{client: mockClient, Name: aws.String("table-name")}

	err := table.Delete(aws.String("id"))
	mockClient.AssertExpectations(t)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.DoesNotExistError{}, err)
}

func TestDeleteOtherError(t *testing.T) {
	mockClient := &mockDynamoClient{}
	mockClient.On("DeleteItem", mock.Anything).Return(
		(*dynamodb.DeleteItemOutput)(nil), errors.New("service unavailable"))
	table := &Table{client: mockClient, Name: aws.String("table-name")}

	err := table.Delete(aws.String("id"))
	mockClient.AssertExpectations(t)
	assert.Error(t, err)
	assert.IsType(t, &genericapi.AWSError{}, err)
}

func TestDelete(t *testing.T) {
	mockClient := &mockDynamoClient{}
	mockClient.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, nil)
	table := &Table{client: mockClient, Name: aws.String("table-name")}

	assert.NoError(t, table.Delete(aws.String("id")))
	mockClient.AssertExpectations(t)
}
