package modelstest

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

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/mock"
)

// MockDDBClient is used to stub out requests to DynamoDB for unit testing.
type MockDDBClient struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
	MockScanAttributes      []map[string]*dynamodb.AttributeValue
	MockItemAttributeOutput map[string]*dynamodb.AttributeValue
	MockQueryAttributes     []map[string]*dynamodb.AttributeValue
	TestErr                 bool
}

// DeleteItem is a mock method to remove an item from a dynamodb table.
func (client *MockDDBClient) DeleteItem(
	input *dynamodb.DeleteItemInput,
) (*dynamodb.DeleteItemOutput, error) {

	args := client.Called(input)
	return args.Get(0).(*dynamodb.DeleteItemOutput), args.Error(1)
}

// UpdateItem is a mock method to update an item from a dynamodb table.
func (client *MockDDBClient) UpdateItem(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*dynamodb.UpdateItemOutput), args.Error(1)
}

// Scan is a mock DynamoDB Scan request.
func (client *MockDDBClient) Scan(input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	if client.TestErr {
		return nil, errors.New("fake dynamodb.Scan error")
	}
	return &dynamodb.ScanOutput{Items: client.MockScanAttributes}, nil
}

// Query is a mock DynamoDB Query request.
func (client *MockDDBClient) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	if client.TestErr {
		return nil, errors.New("fake dynamodb.Query error")
	}
	return &dynamodb.QueryOutput{Items: client.MockQueryAttributes}, nil
}

// PutItem is a mock DynamoDB PutItem request.
func (client *MockDDBClient) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	if client.TestErr {
		return nil, errors.New("fake dynamodb.PutItem error")
	}
	return &dynamodb.PutItemOutput{Attributes: client.MockItemAttributeOutput}, nil
}

func (client *MockDDBClient) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}

// BatchWriteItem is a mock DynamoDB BatchWriteItem request.
func (client *MockDDBClient) BatchWriteItem(input *dynamodb.BatchWriteItemInput) (*dynamodb.BatchWriteItemOutput, error) {
	if client.TestErr {
		return nil, errors.New("fake dynamodb.BatchWriteItem error")
	}
	return &dynamodb.BatchWriteItemOutput{}, nil
}
