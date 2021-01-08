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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/mock"
)

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *mockDynamoDB) DeleteItem(input *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.DeleteItemOutput), args.Error(1)
}

func (m *mockDynamoDB) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

func (m *mockDynamoDB) UpdateItem(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.UpdateItemOutput), args.Error(1)
}

func (m *mockDynamoDB) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.QueryOutput), args.Error(1)
}

func (m *mockDynamoDB) Scan(input *dynamodb.ScanInput) (*dynamodb.ScanOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.ScanOutput), args.Error(1)
}

func (m *mockDynamoDB) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}
func (m *mockDynamoDB) QueryPages(input *dynamodb.QueryInput, function func(*dynamodb.QueryOutput, bool) bool) error {
	args := m.Called(input, function)
	function(mockQueryOutput, true)
	return args.Error(0)
}

func (m *mockDynamoDB) ScanPages(input *dynamodb.ScanInput, function func(*dynamodb.ScanOutput, bool) bool) error {
	args := m.Called(input, function)
	function(mockScanOutput, true)
	return args.Error(0)
}

var mockQueryOutput = &dynamodb.QueryOutput{
	Items: []map[string]*dynamodb.AttributeValue{
		{
			"severity": {
				S: aws.String("INFO"),
			},
			"outputIds": {
				L: []*dynamodb.AttributeValue{{S: aws.String("outputId")}},
			},
		},
	},
}

var mockScanOutput = &dynamodb.ScanOutput{
	Items: []map[string]*dynamodb.AttributeValue{
		{
			"severity": {
				S: aws.String("INFO"),
			},
			"outputIds": {
				L: []*dynamodb.AttributeValue{{S: aws.String("outputId")}},
			},
		},
	},
}
