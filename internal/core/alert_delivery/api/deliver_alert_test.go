package api

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
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	alertModels "github.com/panther-labs/panther/api/lambda/alerts/models"
	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertTable "github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *mockDynamoDB) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}

func TestGetAlert(t *testing.T) {
	// Mock the ddb client and table
	mockDdbClient := &mockDynamoDB{}
	alertsTableClient = &alertTable.AlertsTable{
		AlertsTableName:                    "alertTableName",
		Client:                             mockDdbClient,
		RuleIDCreationTimeIndexName:        "ruleIDCreationTimeIndexName",
		TimePartitionCreationTimeIndexName: "timePartitionCreationTimeIndexName",
	}

	alertID := aws.String("alert-id")
	timeNow := time.Now().UTC()
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliveryModels.Alert{
		AlertID:             alertID,
		AnalysisDescription: aws.String("A test alert"),
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             aws.String("A runbook link"),
		Title:               aws.String("Test Alert"),
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliveryModels.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           timeNow,
		Version:             aws.String("abc"),
	}

	expectedResult := &alertTable.AlertItem{
		AlertID:             aws.StringValue(alert.AlertID),
		RuleID:              alert.AnalysisID,
		RuleVersion:         aws.StringValue(alert.Version),
		RuleDisplayName:     alert.AnalysisName,
		Title:               aws.String("Test Alert"),
		DedupString:         "dedup",
		FirstEventMatchTime: timeNow,
		CreationTime:        timeNow,
		DeliveryResponses:   []*alertModels.DeliveryResponse{{}},
		OutputIds:           alert.OutputIds,
		Severity:            alert.Severity,
	}

	expectedGetItemRequest := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: alertID},
		},
		TableName: aws.String(alertsTableClient.AlertsTableName),
	}

	item, err := dynamodbattribute.MarshalMap(expectedResult)
	require.NoError(t, err)

	mockDdbClient.On("GetItem", expectedGetItemRequest).Return(&dynamodb.GetItemOutput{Item: item}, nil)

	result, err := alertsTableClient.GetAlert(alertID)
	require.NoError(t, err)
	require.Equal(t, expectedResult, result)

	mockDdbClient.AssertExpectations(t)
}

func TestGetAlertOutputMapping(t *testing.T) {
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliveryModels.Alert{
		AlertID:             alertID,
		AnalysisDescription: aws.String("A test alert"),
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             aws.String("A runbook link"),
		Title:               aws.String("Test Alert"),
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliveryModels.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	input := &deliveryModels.DeliverAlertInput{
		AlertID:   aws.StringValue(alertID),
		OutputIds: outputIds,
	}

	outputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String(outputIds[0]),
			OutputType:         aws.String("slack"),
			DefaultForSeverity: []*string{aws.String("INFO")},
		},
		{
			OutputID:           aws.String(outputIds[1]),
			OutputType:         aws.String("customwebhook"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM")},
		},
		{
			OutputID:           aws.String(outputIds[2]),
			OutputType:         aws.String("asana"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
		},
	}

	payload, err := jsoniter.Marshal(outputs)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// AlertOutputMap map[*deliveryModels.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{
		alert: outputs,
	}

	// Need to expire the cache because of other tests
	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5))) // Trigger cache expiration

	result, err := getAlertOutputMapping(alert, input.OutputIds)
	require.NoError(t, err)

	assert.Equal(t, expectedResult, result)
}

func TestGetAlertOutputMappingError(t *testing.T) {
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliveryModels.Alert{
		AlertID:             alertID,
		AnalysisDescription: aws.String("A test alert"),
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             aws.String("A runbook link"),
		Title:               aws.String("Test Alert"),
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliveryModels.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	input := &deliveryModels.DeliverAlertInput{
		AlertID:   aws.StringValue(alertID),
		OutputIds: outputIds,
	}

	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error")).Once()

	// AlertOutputMap map[*deliveryModels.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{}

	// Need to expire the cache because other tests
	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5))) // Trigger cache expiration

	result, err := getAlertOutputMapping(alert, input.OutputIds)
	require.Error(t, err)

	assert.Equal(t, expectedResult, result)
}

func TestGetAlertOutputMappingInvalidOutputIds(t *testing.T) {
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliveryModels.Alert{
		AlertID:             alertID,
		AnalysisDescription: aws.String("A test alert"),
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             aws.String("A runbook link"),
		Title:               aws.String("Test Alert"),
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliveryModels.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	input := &deliveryModels.DeliverAlertInput{
		AlertID:   aws.StringValue(alertID),
		OutputIds: outputIds,
	}

	outputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-a"),
			OutputType:         aws.String("slack"),
			DefaultForSeverity: []*string{aws.String("INFO")},
		},
		{
			OutputID:           aws.String("output-id-b"),
			OutputType:         aws.String("customwebhook"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM")},
		},
		{
			OutputID:           aws.String("output-id-c"),
			OutputType:         aws.String("asana"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
		},
	}

	payload, err := jsoniter.Marshal(outputs)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// AlertOutputMap map[*deliveryModels.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{}

	// Need to expire the cache because other tests
	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5))) // Trigger cache expiration

	result, err := getAlertOutputMapping(alert, input.OutputIds)
	require.Error(t, err)

	assert.Equal(t, expectedResult, result)
}

func TestIntersection(t *testing.T) {
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}
	outputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-1"),
			OutputType:         aws.String("slack"),
			DefaultForSeverity: []*string{aws.String("INFO")},
		},
		{
			OutputID:           aws.String("output-id-b"),
			OutputType:         aws.String("customwebhook"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM")},
		},
		{
			OutputID:           aws.String("output-id-3"),
			OutputType:         aws.String("asana"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
		},
	}

	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-1"),
			OutputType:         aws.String("slack"),
			DefaultForSeverity: []*string{aws.String("INFO")},
		},
		{
			OutputID:           aws.String("output-id-3"),
			OutputType:         aws.String("asana"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
		},
	}

	result := intersection(outputIds, outputs)
	assert.Equal(t, expectedResult, result)
}

func TestReturnIfFailedSuccess(t *testing.T) {
	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}
	timeNow := time.Now().UTC()
	alert := deliveryModels.Alert{
		AlertID:             alertID,
		AnalysisDescription: aws.String("A test alert"),
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             aws.String("A runbook link"),
		Title:               aws.String("Test Alert"),
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliveryModels.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           timeNow,
		Version:             aws.String("abc"),
	}
	dispatchStatuses := []DispatchStatus{
		{
			Alert:        alert,
			OutputID:     outputIds[0],
			Message:      "message",
			StatusCode:   200,
			Success:      true,
			NeedsRetry:   false,
			DispatchedAt: timeNow,
		},
		{
			Alert:        alert,
			OutputID:     outputIds[1],
			Message:      "message",
			StatusCode:   299,
			Success:      true,
			NeedsRetry:   false,
			DispatchedAt: timeNow,
		},
	}

	err := returnIfFailed(dispatchStatuses)
	require.NoError(t, err)
}

func TestReturnIfFailed(t *testing.T) {
	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}
	timeNow := time.Now().UTC()
	alert := deliveryModels.Alert{
		AlertID:             alertID,
		AnalysisDescription: aws.String("A test alert"),
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             aws.String("A runbook link"),
		Title:               aws.String("Test Alert"),
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliveryModels.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           timeNow,
		Version:             aws.String("abc"),
	}
	dispatchStatuses := []DispatchStatus{
		{
			Alert:        alert,
			OutputID:     outputIds[0],
			Message:      "message",
			StatusCode:   401,
			Success:      false,
			NeedsRetry:   false,
			DispatchedAt: timeNow,
		},
		{
			Alert:        alert,
			OutputID:     outputIds[1],
			Message:      "message",
			StatusCode:   299,
			Success:      true,
			NeedsRetry:   false,
			DispatchedAt: timeNow,
		},
	}

	err := returnIfFailed(dispatchStatuses)
	require.Error(t, err)
}
