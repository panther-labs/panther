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
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	policiesclient "github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	alertModel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (m *mockDynamoDB) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*dynamodb.PutItemOutput), args.Error(1)
}

type mockSqs struct {
	sqsiface.SQSAPI
	mock.Mock
}

func (m *mockSqs) SendMessage(input *sqs.SendMessageInput) (*sqs.SendMessageOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SendMessageOutput), args.Error(1)
}

type mockRoundTripper struct {
	http.RoundTripper
	mock.Mock
}

func (m *mockRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	args := m.Called(request)
	return args.Get(0).(*http.Response), args.Error(1)
}

var (
	testAlertDedupEvent = &AlertDedupEvent{
		RuleID:              "ruleId",
		RuleVersion:         "ruleVersion",
		DeduplicationString: "dedupString",
		AlertCount:          10,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC(),
		Severity:            "INFO",
		EventCount:          100,
		LogTypes:            []string{"Log.Type.1", "Log.Type.2"},
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
	ddbMock := &mockDynamoDB{}
	ddbClient = ddbMock

	expectedAlert := &Alert{
		ID:              "8c1b7f1a597d0480354e66c3a6266ccc",
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
	assert.NoError(t, Store(testAlertDedupEvent))
}

// The handler signatures must match those in the LambdaInput struct.
func TestStoreDDBError(t *testing.T) {
	ddbMock := &mockDynamoDB{}
	ddbClient = ddbMock

	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, errors.New("error"))
	assert.Error(t, Store(testAlertDedupEvent))
}

// The handler signatures must match those in the LambdaInput struct.
func TestSendAlert(t *testing.T) {
	sqsMock := &mockSqs{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	policyConfig = policiesclient.DefaultTransportConfig().
		WithHost("host").
		WithBasePath("path")
	policyClient = policiesclient.NewHTTPClientWithConfig(nil, policyConfig)

	expectedAlert := &alertModel.Alert{
		CreatedAt:         aws.Time(testAlertDedupEvent.CreationTime),
		PolicyDescription: aws.String("Description"),
		PolicyID:          aws.String(testAlertDedupEvent.RuleID),
		PolicyVersionID:   aws.String(testAlertDedupEvent.RuleVersion),
		PolicyName:        aws.String("DisplayName"),
		Runbook:           aws.String("Runbook"),
		Severity:          aws.String(testAlertDedupEvent.Severity),
		Tags:              aws.StringSlice([]string{"Tag"}),
		Type:              aws.String(alertModel.RuleType),
		AlertID:           aws.String("8c1b7f1a597d0480354e66c3a6266ccc"),
	}
	expectedMarshaledEvent, err := jsoniter.MarshalToString(expectedAlert)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledEvent),
		QueueUrl:    aws.String("queueUrl"),
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)
	assert.NoError(t, SendAlert(testAlertDedupEvent))
}

func TestSendAlertFailureToGetRule(t *testing.T) {
	sqsMock := &mockSqs{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusInternalServerError), nil).Once()
	assert.Error(t, SendAlert(testAlertDedupEvent))
}

func TestSendAlertFailureToSendSqsMessage(t *testing.T) {
	sqsMock := &mockSqs{}
	sqsClient = sqsMock

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(testRuleResponse, http.StatusOK), nil).Once()
	sqsMock.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, errors.New("error"))
	assert.Error(t, SendAlert(testAlertDedupEvent))
}

func generateResponse(body interface{}, httpCode int) *http.Response {
	serializedBody, _ := jsoniter.MarshalToString(body)
	return &http.Response{StatusCode: httpCode, Body: ioutil.NopCloser(strings.NewReader(serializedBody))}
}
