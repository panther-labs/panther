package forwarder

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *mockDynamoDB) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

var testAlertDedupEvent = &AlertDedupEvent{
	RuleID:              "ruleId",
	DeduplicationString: "dedupString",
	AlertCount:          10,
	CreationTime:        time.Now().UTC(),
	UpdateTime:          time.Now().UTC(),
	EventPerLogType: map[string]int64{
		"LogType1": 5,
		"LogType2": 10,
	},
}

func init() {
	alertsTable = "alertsTable"
}

// The handler signatures must match those in the LambdaInput struct.
func TestProcess(t *testing.T) {
	ddbMock := &mockDynamoDB{}
	ddbClient = ddbMock

	expectedAlert := &Alert{
		ID:              "ruleId:dedupString:10",
		TimePartition:   "defaultPartition",
		AlertDedupEvent: *testAlertDedupEvent,
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	assert.NoError(t, Process(testAlertDedupEvent))
}

// The handler signatures must match those in the LambdaInput struct.
func TestProcessDDBError(t *testing.T) {
	ddbMock := &mockDynamoDB{}
	ddbClient = ddbMock

	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, errors.New("error"))
	assert.Error(t, Process(testAlertDedupEvent))
}
