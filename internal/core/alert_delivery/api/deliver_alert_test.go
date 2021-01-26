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
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	alertModels "github.com/panther-labs/panther/api/lambda/alerts/models"
	analysisModels "github.com/panther-labs/panther/api/lambda/analysis/models"
	complianceModels "github.com/panther-labs/panther/api/lambda/compliance/models"
	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertTable "github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestGetAlert(t *testing.T) {
	// Mock the ddb client and table
	mockDdbClient := &testutils.DynamoDBMock{}
	alertsTableClient = &alertTable.AlertsTable{
		AlertsTableName:                    "alertTableName",
		Client:                             mockDdbClient,
		RuleIDCreationTimeIndexName:        "ruleIDCreationTimeIndexName",
		TimePartitionCreationTimeIndexName: "timePartitionCreationTimeIndexName",
	}

	alertID := aws.String("alert-id")
	timeNow := time.Now().UTC()
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: "A test alert",
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             "A runbook link",
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliverymodel.RuleType,
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
		Title:               "Test Alert",
		DedupString:         "dedup",
		FirstEventMatchTime: timeNow,
		CreationTime:        timeNow,
		DeliveryResponses:   []*alertModels.DeliveryResponse{{}},
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

	result, err := alertsTableClient.GetAlert(*alertID)
	require.NoError(t, err)
	require.Equal(t, expectedResult, result)

	mockDdbClient.AssertExpectations(t)
}

func TestPopulateAlert(t *testing.T) {
	mockAnalysisClient := &gatewayapi.MockClient{}
	analysisClient = mockAnalysisClient

	alertID := aws.String("alert-id")
	timeNow := time.Now().UTC()
	versionID := "version"
	analysisDisplayName := aws.String("Test Analysis Name")
	description := "A test aler"
	analysisID := "Test.Analysis.ID"
	runbook := "A runbook link"
	severity := complianceModels.SeverityInfo
	tags := []string{"test", "alert"}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: description,
		AnalysisID:          analysisID,
		AnalysisName:        analysisDisplayName,
		Runbook:             runbook,
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                tags,
		Type:                deliverymodel.RuleType,
		OutputIds:           []string{},
		Severity:            string(severity),
		CreatedAt:           timeNow,
		Version:             aws.String(versionID),
		IsResent:            true,
	}

	alertItem := &alertTable.AlertItem{
		AlertID:             *alertID,
		Type:                deliverymodel.RuleType,
		Description:         aws.String(description),
		RuleID:              analysisID,
		RuleVersion:         versionID,
		RuleDisplayName:     analysisDisplayName,
		Runbook:             aws.String(runbook),
		Title:               "Test Alert",
		DedupString:         "dedup",
		FirstEventMatchTime: timeNow,
		CreationTime:        timeNow,
		DeliveryResponses:   []*alertModels.DeliveryResponse{{}},
		Severity:            alert.Severity,
	}

	rule := &analysisModels.Rule{
		CreatedAt:          timeNow,
		CreatedBy:          "user-id",
		DedupPeriodMinutes: 15,
		Description:        description,
		DisplayName:        *analysisDisplayName,
		Enabled:            true,
		ID:                 analysisID,
		LastModified:       timeNow,
		LastModifiedBy:     "user-id",
		LogTypes:           []string{"log-type"},
		OutputIDs:          []string{},
		Runbook:            runbook,
		Severity:           severity,
		Tags:               tags,
		VersionID:          "version",
	}

	getRuleInput := &analysisModels.LambdaInput{
		GetRule: &analysisModels.GetRuleInput{
			ID:        analysisID,
			VersionID: "version",
		},
	}
	mockAnalysisClient.On("Invoke", getRuleInput, &analysisModels.Rule{}).Return(
		http.StatusOK, nil, rule).Once()

	expectedAlert, err := populateAlertData(alertItem)
	require.NoError(t, err)
	require.Equal(t, alert, expectedAlert)
	mockAnalysisClient.AssertExpectations(t)
}

func TestGetAlertOutputMapping(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: "A test alert",
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             "A runbook link",
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliverymodel.RuleType,
		OutputIds:           []string{},
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	input := &deliverymodel.DeliverAlertInput{
		AlertID:   aws.StringValue(alertID),
		OutputIds: outputIds,
	}

	outputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String(outputIds[0]),
			OutputType:         aws.String("slack"),
			DefaultForSeverity: []*string{aws.String("INFO")},
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
		{
			OutputID:           aws.String(outputIds[1]),
			OutputType:         aws.String("customwebhook"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM")},
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
		{
			OutputID:           aws.String(outputIds[2]),
			OutputType:         aws.String("asana"),
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
	}

	payload, err := jsoniter.Marshal(outputs)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{
		alert: outputs,
	}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	result, err := getAlertOutputMapping(alert, input.OutputIds)
	require.NoError(t, err)

	assert.Equal(t, expectedResult, result)
}

func TestGetAlertOutputMappingError(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: "A test alert",
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             "A runbook link",
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliverymodel.RuleType,
		OutputIds:           []string{},
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	input := &deliverymodel.DeliverAlertInput{
		AlertID:   aws.StringValue(alertID),
		OutputIds: outputIds,
	}

	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error")).Once()

	// AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	result, err := getAlertOutputMapping(alert, input.OutputIds)
	require.Error(t, err)

	assert.Equal(t, expectedResult, result)
}

func TestGetAlertOutputMappingInvalidOutputIds(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: "A test alert",
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             "A runbook link",
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliverymodel.RuleType,
		OutputIds:           []string{},
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	input := &deliverymodel.DeliverAlertInput{
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

	// AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	result, err := getAlertOutputMapping(alert, input.OutputIds)
	require.Error(t, err)

	assert.Equal(t, expectedResult, result)
}

func TestIntersection(t *testing.T) {
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}
	outputs := []*outputModels.AlertOutput{
		{
			OutputID: aws.String("output-id-1"),
		},
		{
			OutputID: aws.String("output-id-b"),
		},
		{
			OutputID: aws.String("output-id-3"),
		},
	}

	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID: aws.String("output-id-1"),
		},
		{
			OutputID: aws.String("output-id-3"),
		},
	}

	result := intersection(outputIds, outputs)
	assert.Equal(t, expectedResult, result)
}

func TestDifference(t *testing.T) {
	outputsA := []*outputModels.AlertOutput{
		{
			OutputID: aws.String("output-id-1"),
		},
		{
			OutputID: aws.String("output-id-2"),
		},
		{
			OutputID: aws.String("output-id-3"),
		},
	}

	outputsB := []*outputModels.AlertOutput{
		{
			OutputID: aws.String("output-id-1"),
		},
		{
			OutputID: aws.String("output-id-b"),
		},
		{
			OutputID: aws.String("output-id-3"),
		},
	}

	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID: aws.String("output-id-b"),
		},
	}

	result := difference(outputsA, outputsB)
	assert.Equal(t, expectedResult, result)
}
