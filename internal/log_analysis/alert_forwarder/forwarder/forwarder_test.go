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
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
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
		Severity:            "INFO",
		EventCount:          100,
		LogTypes:            []string{"Log.Type.1", "Log.Type.2"},
		Title:               aws.String("test title"),
	}

	newAlertDedupEvent = &AlertDedupEvent{
		RuleID:              oldAlertDedupEvent.RuleID,
		RuleVersion:         oldAlertDedupEvent.RuleVersion,
		DeduplicationString: oldAlertDedupEvent.DeduplicationString,
		AlertCount:          oldAlertDedupEvent.AlertCount + 1,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC(),
		EventCount:          oldAlertDedupEvent.EventCount,
		Severity:            oldAlertDedupEvent.Severity,
		LogTypes:            oldAlertDedupEvent.LogTypes,
		Title:               oldAlertDedupEvent.Title,
	}

	testRuleResponse = &models.Rule{
		Description: "Description",
		DisplayName: "DisplayName",
		Runbook:     "Runbook",
		Tags:        []string{"Tag"},
	}
)

func init() {
	env.AlertsTable = "alertsTable"
	env.AlertingQueueURL = "queueUrl"
}

func TestStore(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	expectedAlert := &Alert{
		ID:              "8c1b7f1a597d0480354e66c3a6266ccc",
		TimePartition:   "defaultPartition",
		AlertDedupEvent: *oldAlertDedupEvent,
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	assert.NoError(t, HandleUpdatingAlertInfo(oldAlertDedupEvent))
}

// The handler signatures must match those in the LambdaInput struct.
func TestStoreDDBError(t *testing.T) {
	ddbMock := &testutils.DynamoDBMock{}
	ddbClient = ddbMock

	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, errors.New("error"))
	assert.Error(t, HandleUpdatingAlertInfo(oldAlertDedupEvent))
}

func TestSendDoNotSendNotification(t *testing.T) {
	assert.NoError(t, HandleSendingAlertNotification(oldAlertDedupEvent, oldAlertDedupEvent))
}

func TestSendAlert(t *testing.T) {
	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost("host").
		WithBasePath("path")
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)

	expectedAlert := &alertModel.Alert{
		CreatedAt:         aws.Time(newAlertDedupEvent.CreationTime),
		PolicyDescription: aws.String("Description"),
		PolicyID:          aws.String(newAlertDedupEvent.RuleID),
		PolicyVersionID:   aws.String(newAlertDedupEvent.RuleVersion),
		PolicyName:        aws.String("DisplayName"),
		Runbook:           aws.String("Runbook"),
		Severity:          aws.String(newAlertDedupEvent.Severity),
		Tags:              aws.StringSlice([]string{"Tag"}),
		Type:              aws.String(alertModel.RuleType),
		AlertID:           aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:             aws.String("test title"),
	}
	expectedMarshaledEvent, err := jsoniter.MarshalToString(expectedAlert)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledEvent),
		QueueUrl:    aws.String("queueUrl"),
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)
	assert.NoError(t, HandleSendingAlertNotification(nil, newAlertDedupEvent))
}

func TestSendAlertWithoutTitle(t *testing.T) {
	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost("host").
		WithBasePath("path")
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)

	testEvent := &AlertDedupEvent{
		RuleID:              newAlertDedupEvent.RuleID,
		RuleVersion:         newAlertDedupEvent.RuleVersion,
		DeduplicationString: newAlertDedupEvent.DeduplicationString,
		AlertCount:          newAlertDedupEvent.AlertCount,
		CreationTime:        newAlertDedupEvent.CreationTime,
		UpdateTime:          newAlertDedupEvent.UpdateTime,
		Severity:            newAlertDedupEvent.Severity,
		EventCount:          newAlertDedupEvent.EventCount,
		LogTypes:            newAlertDedupEvent.LogTypes,
		Title:               nil,
	}

	expectedAlert := &alertModel.Alert{
		CreatedAt:         aws.Time(testEvent.CreationTime),
		PolicyDescription: aws.String("Description"),
		PolicyID:          aws.String(testEvent.RuleID),
		PolicyVersionID:   aws.String(testEvent.RuleVersion),
		PolicyName:        aws.String("DisplayName"),
		Runbook:           aws.String("Runbook"),
		Severity:          aws.String(oldAlertDedupEvent.Severity),
		Tags:              aws.StringSlice([]string{"Tag"}),
		Type:              aws.String(alertModel.RuleType),
		AlertID:           aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
	}
	expectedMarshaledEvent, err := jsoniter.MarshalToString(expectedAlert)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledEvent),
		QueueUrl:    aws.String("queueUrl"),
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)
	assert.NoError(t, HandleSendingAlertNotification(oldAlertDedupEvent, testEvent))
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestSendAlertFailureToGetRule(t *testing.T) {
	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusInternalServerError), nil).Once()
	assert.Error(t, HandleSendingAlertNotification(oldAlertDedupEvent, newAlertDedupEvent))
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestSendAlertRuleDoesntExist(t *testing.T) {
	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusNotFound), nil).Once()
	assert.NoError(t, HandleSendingAlertNotification(oldAlertDedupEvent, newAlertDedupEvent))
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestSendAlertFailureToSendSqsMessage(t *testing.T) {
	sqsMock := &testutils.SqsMock{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, errors.New("error"))
	assert.Error(t, HandleSendingAlertNotification(oldAlertDedupEvent, newAlertDedupEvent))
	sqsMock.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func generateResponse(body interface{}, httpCode int) *http.Response {
	serializedBody, _ := jsoniter.MarshalToString(body)
	return &http.Response{StatusCode: httpCode, Body: ioutil.NopCloser(strings.NewReader(serializedBody))}
}
