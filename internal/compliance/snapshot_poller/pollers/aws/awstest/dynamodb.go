package awstest

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/mock"
)

// Example DynamoDB return values
var (
	ExampleTableName = aws.String("example-table")

	ExampleDescribeTableOutput = &dynamodb.DescribeTableOutput{
		Table: &dynamodb.TableDescription{
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				{
					AttributeName: aws.String("attr_1"),
					AttributeType: aws.String("S"),
				},
			},
			TableName: ExampleTableName,
			KeySchema: []*dynamodb.KeySchemaElement{
				{
					AttributeName: aws.String("primary_key"),
					KeyType:       aws.String("HASH"),
				},
			},
			TableStatus:      aws.String("ACTIVE"),
			CreationDateTime: &ExampleTime,
			ProvisionedThroughput: &dynamodb.ProvisionedThroughputDescription{
				NumberOfDecreasesToday: aws.Int64(0),
				ReadCapacityUnits:      aws.Int64(5),
				WriteCapacityUnits:     aws.Int64(5),
			},
			TableSizeBytes: aws.Int64(1000),
			ItemCount:      aws.Int64(10),
			TableArn:       aws.String("arn:aws:dynamodb:us-west-2:123456789012:table/example-table"),
			TableId:        aws.String("1234abcd-12ab-aabb-123456abcde"),
			BillingModeSummary: &dynamodb.BillingModeSummary{
				BillingMode:                       aws.String("PROVISIONED"),
				LastUpdateToPayPerRequestDateTime: &ExampleTime,
			},
			GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndexDescription{
				{
					IndexName: aws.String("index-1"),
					KeySchema: []*dynamodb.KeySchemaElement{
						{
							AttributeName: aws.String("attr-1"),
							KeyType:       aws.String("HASH"),
						},
					},
					Projection: &dynamodb.Projection{
						ProjectionType: aws.String("ALL"),
					},
					IndexStatus: aws.String("ACTIVE"),
					ProvisionedThroughput: &dynamodb.ProvisionedThroughputDescription{
						LastDecreaseDateTime:   &ExampleTime,
						LastIncreaseDateTime:   &ExampleTime,
						NumberOfDecreasesToday: aws.Int64(0),
						ReadCapacityUnits:      aws.Int64(5),
						WriteCapacityUnits:     aws.Int64(5),
					},
					IndexSizeBytes: aws.Int64(500),
					ItemCount:      aws.Int64(5),
					IndexArn:       aws.String("arn:aws:dynamodb:us-west-2:123456789012:table/example-table/index/index-1"),
				},
			},
		},
	}

	ExampleListTablesOutput = &dynamodb.ListTablesOutput{
		TableNames: []*string{
			ExampleTableName,
		},
	}

	ExampleListTablesOutputContinue = &dynamodb.ListTablesOutput{
		TableNames: []*string{
			ExampleTableName,
			ExampleTableName,
		},
		LastEvaluatedTableName: ExampleTableName,
	}

	ExampleListTagsOfResource = &dynamodb.ListTagsOfResourceOutput{
		Tags: []*dynamodb.Tag{
			{
				Key:   aws.String("KeyName1"),
				Value: aws.String("Value1"),
			},
		},
	}

	ExampleDescribeTimeToLive = &dynamodb.DescribeTimeToLiveOutput{
		TimeToLiveDescription: &dynamodb.TimeToLiveDescription{
			TimeToLiveStatus: aws.String("ENABLED"),
			AttributeName:    aws.String("expireTime"),
		},
	}

	svcDynamoDBSetupCalls = map[string]func(*MockDynamoDB){
		"ListTablesPages": func(svc *MockDynamoDB) {
			svc.On("ListTablesPages", mock.Anything).
				Return(nil)
		},
		"DescribeTable": func(svc *MockDynamoDB) {
			svc.On("DescribeTable", mock.Anything).
				Return(ExampleDescribeTableOutput, nil)
		},
		"ListTagsOfResource": func(svc *MockDynamoDB) {
			svc.On("ListTagsOfResource", mock.Anything).
				Return(ExampleListTagsOfResource, nil)
		},
		"DescribeTimeToLive": func(svc *MockDynamoDB) {
			svc.On("DescribeTimeToLive", mock.Anything).
				Return(ExampleDescribeTimeToLive, nil)
		},
	}

	svcDynamoDBSetupCallsError = map[string]func(*MockDynamoDB){
		"ListTablesPages": func(svc *MockDynamoDB) {
			svc.On("ListTablesPages", mock.Anything).
				Return(errors.New("DynamoDB.ListTablesPages error"))
		},
		"DescribeTable": func(svc *MockDynamoDB) {
			svc.On("DescribeTable", mock.Anything).
				Return(&dynamodb.DescribeTableOutput{},
					errors.New("DynamoDB.DescribeTable error"),
				)
		},
		"ListTagsOfResource": func(svc *MockDynamoDB) {
			svc.On("ListTagsOfResource", mock.Anything).
				Return(&dynamodb.ListTagsOfResourceOutput{},
					errors.New("DynamoDB.ListTagsOfResource error"),
				)
		},
		"DescribeTimeToLive": func(svc *MockDynamoDB) {
			svc.On("DescribeTimeToLive", mock.Anything).
				Return(&dynamodb.DescribeTimeToLiveOutput{},
					errors.New("DynamoDB.DescribeTimeToLive error"),
				)
		},
	}

	MockDynamoDBForSetup = &MockDynamoDB{}
)

// DynamoDB mock

// SetupMockDynamoDB is used to override the DynamoDB Client initializer
func SetupMockDynamoDB(_ *session.Session, _ *aws.Config) interface{} {
	return MockDynamoDBForSetup
}

// MockDynamoDB is a mock Dynamo DB client
type MockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

// BuildMockDynamoDBSvc builds and returns a MockDynamoDB struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockDynamoDBSvc(funcs []string) (mockSvc *MockDynamoDB) {
	mockSvc = &MockDynamoDB{}
	for _, f := range funcs {
		svcDynamoDBSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockDynamoDBSvcError builds and returns a MockDynamoDB struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockDynamoDBSvcError(funcs []string) (mockSvc *MockDynamoDB) {
	mockSvc = &MockDynamoDB{}
	for _, f := range funcs {
		svcDynamoDBSetupCallsError[f](mockSvc)
	}
	return
}

// BuildDynamoDBServiceSvcAll builds and returns a MockDynamoDB struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockDynamoDBSvcAll() (mockSvc *MockDynamoDB) {
	mockSvc = &MockDynamoDB{}
	for _, f := range svcDynamoDBSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockDynamoDBSvcAllError builds and returns a MockDynamoDB struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockDynamoDBSvcAllError() (mockSvc *MockDynamoDB) {
	mockSvc = &MockDynamoDB{}
	for _, f := range svcDynamoDBSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockDynamoDB) ListTablesPages(
	in *dynamodb.ListTablesInput,
	paginationFunction func(*dynamodb.ListTablesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListTablesOutput, true)
	return args.Error(0)
}

func (m *MockDynamoDB) DescribeTable(in *dynamodb.DescribeTableInput) (*dynamodb.DescribeTableOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*dynamodb.DescribeTableOutput), args.Error(1)
}

func (m *MockDynamoDB) ListTagsOfResource(in *dynamodb.ListTagsOfResourceInput) (*dynamodb.ListTagsOfResourceOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*dynamodb.ListTagsOfResourceOutput), args.Error(1)
}

func (m *MockDynamoDB) DescribeTimeToLive(in *dynamodb.DescribeTimeToLiveInput) (*dynamodb.DescribeTimeToLiveOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*dynamodb.DescribeTimeToLiveOutput), args.Error(1)
}
