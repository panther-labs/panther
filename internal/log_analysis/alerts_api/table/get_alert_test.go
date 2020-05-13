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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetAlert(t *testing.T) {
	mockDdbClient := &mockDynamoDB{}
	table := AlertsTable{
		AlertsTableName:                    "alertsTableName",
		RuleIDCreationTimeIndexName:        "ruleIDCreationTimeIndexName",
		TimePartitionCreationTimeIndexName: "timePartitionCreationTimeIndexName",
		Client:                             mockDdbClient,
	}

	expectedGetItemRequest := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String("alertId")},
		},
		TableName: aws.String(table.AlertsTableName),
	}

	expectedAlert := &AlertItem{
		AlertID:      "alertId",
		RuleID:       "ruleId",
		CreationTime: time.Now().UTC(),
		UpdateTime:   time.Now().UTC(),
		Severity:     "INFO",
		EventCount:   10,
		LogTypes:     []string{"logtype"},
	}

	item, err := dynamodbattribute.MarshalMap(expectedAlert)
	require.NoError(t, err)

	mockDdbClient.On("GetItem", expectedGetItemRequest).Return(&dynamodb.GetItemOutput{Item: item}, nil)

	result, err := table.GetAlert(aws.String("alertId"))
	require.NoError(t, err)
	require.Equal(t, expectedAlert, result)
}

func TestGetAlertDoesNotExist(t *testing.T) {
	mockDdbClient := &mockDynamoDB{}
	table := AlertsTable{
		AlertsTableName:                    "alertsTableName",
		RuleIDCreationTimeIndexName:        "ruleIDCreationTimeIndexName",
		TimePartitionCreationTimeIndexName: "timePartitionCreationTimeIndexName",
		Client:                             mockDdbClient,
	}

	mockDdbClient.On("GetItem", mock.Anything).Return(&dynamodb.GetItemOutput{}, nil)

	result, err := table.GetAlert(aws.String("alertId"))
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestGetAlertErrorQueryingDynamo(t *testing.T) {
	mockDdbClient := &mockDynamoDB{}
	table := AlertsTable{
		AlertsTableName:                    "alertsTableName",
		RuleIDCreationTimeIndexName:        "ruleIDCreationTimeIndexName",
		TimePartitionCreationTimeIndexName: "timePartitionCreationTimeIndexName",
		Client:                             mockDdbClient,
	}

	mockDdbClient.On("GetItem", mock.Anything).Return(&dynamodb.GetItemOutput{}, errors.New("test"))

	_, err := table.GetAlert(aws.String("alertId"))
	require.Error(t, err)
}

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *mockDynamoDB) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}
