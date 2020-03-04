package table

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
		Key:                      map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String("alertId")},
		},
		TableName:                aws.String(table.AlertsTableName),
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
