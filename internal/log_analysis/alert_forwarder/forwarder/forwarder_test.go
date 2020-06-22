package forwarder

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
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	policiesclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	alertModel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

type mockRoundTripper struct {
	http.RoundTripper
	mock.Mock
}

func (m *mockRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	args := m.Called(request)
	return args.Get(0).(*http.Response), args.Error(1)
}

var (
	oldAlertDedupEvent = &AlertDedupEvent{
		RuleID:              "ruleId",
		RuleVersion:         "ruleVersion",
		DeduplicationString: "dedupString",
		AlertCount:          10,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC(),
		EventCount:          100,
		LogTypes:            []string{"Log.Type.1", "Log.Type.2"},
		GeneratedTitle:      aws.String("test title"),
	}

	newAlertDedupEvent = &AlertDedupEvent{
		RuleID:              oldAlertDedupEvent.RuleID,
		RuleVersion:         oldAlertDedupEvent.RuleVersion,
		DeduplicationString: oldAlertDedupEvent.DeduplicationString,
		AlertCount:          oldAlertDedupEvent.AlertCount + 1,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC(),
		EventCount:          oldAlertDedupEvent.EventCount,
		LogTypes:            oldAlertDedupEvent.LogTypes,
		GeneratedTitle:      oldAlertDedupEvent.GeneratedTitle,
	}

	testRuleResponse = &models.Rule{
		ID:          "ruleId",
		Description: "Description",
		DisplayName: "DisplayName",
		Severity:    "INFO",
		Runbook:     "Runbook",
		Tags:        []string{"Tag"},
	}
)

func init() {
	env.AlertsTable = "alertsTable"
	env.AlertingQueueURL = "queueUrl"
}

func TestHandleStoreAndSendNotification(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost("host").
		WithBasePath("path")
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEvent.CreationTime,
		AnalysisDescription: aws.String(string(testRuleResponse.Description)),
		AnalysisID:          newAlertDedupEvent.RuleID,
		Version:             aws.String(newAlertDedupEvent.RuleVersion),
		AnalysisName:        aws.String(string(testRuleResponse.DisplayName)),
		Runbook:             aws.String(string(testRuleResponse.Runbook)),
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                alertModel.RuleType,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               newAlertDedupEvent.GeneratedTitle,
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledAlertNotification),
		QueueUrl:    aws.String("queueUrl"),
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &Alert{
		ID:              "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:   "defaultPartition",
		Severity:        string(testRuleResponse.Severity),
		RuleDisplayName: aws.String(string(testRuleResponse.DisplayName)),
		Title:           aws.StringValue(newAlertDedupEvent.GeneratedTitle),
		AlertDedupEvent: *newAlertDedupEvent,
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	assert.NoError(t, Handle(oldAlertDedupEvent, newAlertDedupEvent))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleStoreAndSendNotificationNoRuleDisplayNameNoTitle(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost("host").
		WithBasePath("path")
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)

	newAlertDedupEventWithoutTitle := &AlertDedupEvent{
		RuleID:              oldAlertDedupEvent.RuleID,
		RuleVersion:         oldAlertDedupEvent.RuleVersion,
		DeduplicationString: oldAlertDedupEvent.DeduplicationString,
		AlertCount:          oldAlertDedupEvent.AlertCount + 1,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC(),
		EventCount:          oldAlertDedupEvent.EventCount,
		LogTypes:            oldAlertDedupEvent.LogTypes,
	}

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEventWithoutTitle.CreationTime,
		AnalysisDescription: aws.String(string(testRuleResponse.Description)),
		AnalysisID:          newAlertDedupEventWithoutTitle.RuleID,
		Version:             aws.String(newAlertDedupEventWithoutTitle.RuleVersion),
		Runbook:             aws.String(string(testRuleResponse.Runbook)),
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                alertModel.RuleType,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               aws.String(newAlertDedupEventWithoutTitle.RuleID),
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledAlertNotification),
		QueueUrl:    aws.String("queueUrl"),
	}

	testRuleResponseWithoutDisplayName := &models.Rule{
		ID:          "ruleId",
		Description: "Description",
		Severity:    "INFO",
		Runbook:     "Runbook",
		Tags:        []string{"Tag"},
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponseWithoutDisplayName, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &Alert{
		ID:              "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:   "defaultPartition",
		Severity:        string(testRuleResponse.Severity),
		Title:           newAlertDedupEventWithoutTitle.RuleID,
		AlertDedupEvent: *newAlertDedupEventWithoutTitle,
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	assert.NoError(t, Handle(oldAlertDedupEvent, newAlertDedupEventWithoutTitle))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleStoreAndSendNotificationNoGeneratedTitle(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost("host").
		WithBasePath("path")
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEvent.CreationTime,
		AnalysisDescription: aws.String(string(testRuleResponse.Description)),
		AnalysisID:          newAlertDedupEvent.RuleID,
		Version:             aws.String(newAlertDedupEvent.RuleVersion),
		AnalysisName:        aws.String(string(testRuleResponse.DisplayName)),
		Runbook:             aws.String(string(testRuleResponse.Runbook)),
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                alertModel.RuleType,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               aws.String("DisplayName"),
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledAlertNotification),
		QueueUrl:    aws.String("queueUrl"),
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &Alert{
		ID:              "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:   "defaultPartition",
		Severity:        string(testRuleResponse.Severity),
		RuleDisplayName: aws.String(string(testRuleResponse.DisplayName)),
		Title:           "DisplayName",
		AlertDedupEvent: *newAlertDedupEvent,
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	dedupEventWithoutTitle := &AlertDedupEvent{
		RuleID:              newAlertDedupEvent.RuleID,
		RuleVersion:         newAlertDedupEvent.RuleVersion,
		DeduplicationString: newAlertDedupEvent.DeduplicationString,
		AlertCount:          newAlertDedupEvent.AlertCount,
		CreationTime:        newAlertDedupEvent.CreationTime,
		UpdateTime:          newAlertDedupEvent.UpdateTime,
		EventCount:          newAlertDedupEvent.EventCount,
		LogTypes:            newAlertDedupEvent.LogTypes,
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	assert.NoError(t, Handle(oldAlertDedupEvent, dedupEventWithoutTitle))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleStoreAndSendNotificationNilOldDedup(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost("host").
		WithBasePath("path")
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEvent.CreationTime,
		AnalysisDescription: aws.String(string(testRuleResponse.Description)),
		AnalysisID:          newAlertDedupEvent.RuleID,
		AnalysisName:        aws.String(string(testRuleResponse.DisplayName)),
		Version:             aws.String(newAlertDedupEvent.RuleVersion),
		Runbook:             aws.String(string(testRuleResponse.Runbook)),
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                alertModel.RuleType,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               newAlertDedupEvent.GeneratedTitle,
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledAlertNotification),
		QueueUrl:    aws.String("queueUrl"),
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &Alert{
		ID:              "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:   "defaultPartition",
		Severity:        string(testRuleResponse.Severity),
		Title:           aws.StringValue(newAlertDedupEvent.GeneratedTitle),
		RuleDisplayName: aws.String(string(testRuleResponse.DisplayName)),
		AlertDedupEvent: *newAlertDedupEvent,
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	require.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	require.NoError(t, Handle(nil, newAlertDedupEvent))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleUpdateAlert(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	dedupEventWithUpdatedFields := &AlertDedupEvent{
		RuleID:              newAlertDedupEvent.RuleID,
		RuleVersion:         newAlertDedupEvent.RuleVersion,
		DeduplicationString: newAlertDedupEvent.DeduplicationString,
		AlertCount:          newAlertDedupEvent.AlertCount,
		CreationTime:        newAlertDedupEvent.CreationTime,
		UpdateTime:          newAlertDedupEvent.UpdateTime.Add(1 * time.Minute),
		EventCount:          newAlertDedupEvent.EventCount + 10,
		LogTypes:            append(newAlertDedupEvent.LogTypes, "New.Log.Type"),
		GeneratedTitle:      newAlertDedupEvent.GeneratedTitle,
	}

	updateExpression := expression.
		Set(expression.Name("eventCount"), expression.Value(aws.Int64(dedupEventWithUpdatedFields.EventCount))).
		Set(expression.Name("logTypes"), expression.Value(aws.StringSlice(dedupEventWithUpdatedFields.LogTypes))).
		Set(expression.Name("updateTime"), expression.Value(aws.Time(dedupEventWithUpdatedFields.UpdateTime)))
	expr, err := expression.NewBuilder().WithUpdate(updateExpression).Build()
	require.NoError(t, err)

	expectedUpdateItemInput := &dynamodb.UpdateItemInput{
		TableName: aws.String("alertsTable"),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String("b25dc23fb2a0b362da8428dbec1381a8")},
		},
		UpdateExpression:          expr.Update(),
		ExpressionAttributeValues: expr.Values(),
		ExpressionAttributeNames:  expr.Names(),
	}

	ddbMock.On("UpdateItem", expectedUpdateItemInput).Return(&dynamodb.UpdateItemOutput{}, nil)
	assert.NoError(t, Handle(newAlertDedupEvent, dedupEventWithUpdatedFields))

	ddbMock.AssertExpectations(t)
}

func TestHandleUpdateAlertDDBError(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	dedupEventWithUpdatedFields := &AlertDedupEvent{
		RuleID:              newAlertDedupEvent.RuleID,
		RuleVersion:         newAlertDedupEvent.RuleVersion,
		DeduplicationString: newAlertDedupEvent.DeduplicationString,
		AlertCount:          newAlertDedupEvent.AlertCount,
		CreationTime:        newAlertDedupEvent.CreationTime,
		UpdateTime:          newAlertDedupEvent.UpdateTime.Add(1 * time.Minute),
		EventCount:          newAlertDedupEvent.EventCount + 10,
		LogTypes:            append(newAlertDedupEvent.LogTypes, "New.Log.Type"),
		GeneratedTitle:      newAlertDedupEvent.GeneratedTitle,
	}

	ddbMock.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, errors.New("error"))
	assert.Error(t, Handle(newAlertDedupEvent, dedupEventWithUpdatedFields))
}

func generateResponse(body interface{}, httpCode int) *http.Response {
	serializedBody, _ := jsoniter.MarshalToString(body)
	return &http.Response{StatusCode: httpCode, Body: ioutil.NopCloser(strings.NewReader(serializedBody))}
}
