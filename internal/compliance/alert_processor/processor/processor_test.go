package processor

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
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/gateway/compliance/models"
	"github.com/panther-labs/panther/internal/compliance/alert_processor/models"
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

func TestHandleEventWithAlert(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	input := &models.ComplianceNotification{
		ResourceID:      aws.String("test-resource"),
		PolicyID:        aws.String("test-policy"),
		PolicyVersionID: aws.String("test-version"),
		ShouldAlert:     aws.Bool(true),
		Timestamp:       aws.Time(time.Now()),
	}

	complianceResponse := &compliancemodels.ComplianceStatus{
		LastUpdated:    compliancemodels.LastUpdated(time.Now()),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusFAIL,
		Suppressed:     false,
	}

	policyResponse := &analysismodels.Policy{
		AutoRemediationID: "test-autoremediation-id",
	}

	// mock call to compliance-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(complianceResponse, http.StatusOK), nil).Once()
	// mock call to analysis-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(policyResponse, http.StatusOK), nil).Once()
	// mock call to remediate-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse("", http.StatusOK), nil).Once()
	mockDdbClient.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, nil)

	require.NoError(t, Handle(input))

	// Verifying request to fetch compliance information
	httpRequest := mockRoundTripper.Calls[0].Arguments[0].(*http.Request)
	assert.Equal(t, "policyId=test-policy&resourceId=test-resource", httpRequest.URL.RawQuery)

	mockDdbClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleEventWithAlertButNoAutoRemediationID(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	input := &models.ComplianceNotification{
		ResourceID:      aws.String("test-resource"),
		PolicyID:        aws.String("test-policy"),
		PolicyVersionID: aws.String("test-version"),
		ShouldAlert:     aws.Bool(true),
		Timestamp:       aws.Time(time.Now()),
	}

	complianceResponse := &compliancemodels.ComplianceStatus{
		LastUpdated:    compliancemodels.LastUpdated(time.Now()),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusFAIL,
		Suppressed:     false,
	}

	policyResponse := &analysismodels.Policy{} // no AutoRemediationID

	// mock call to compliance-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(complianceResponse, http.StatusOK), nil).Once()
	// mock call to analysis-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(policyResponse, http.StatusOK), nil).Once()
	// should NOT call remediation api!

	mockDdbClient.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, nil)

	require.NoError(t, Handle(input))

	// Verifying request to fetch compliance information
	httpRequest := mockRoundTripper.Calls[0].Arguments[0].(*http.Request)
	assert.Equal(t, "policyId=test-policy&resourceId=test-resource", httpRequest.URL.RawQuery)

	mockDdbClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleEventWithoutAlert(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	input := &models.ComplianceNotification{
		ResourceID:      aws.String("test-resource"),
		PolicyID:        aws.String("test-policy"),
		PolicyVersionID: aws.String("test-version"),
		ShouldAlert:     aws.Bool(false),
	}

	complianceResponse := &compliancemodels.ComplianceStatus{
		LastUpdated:    compliancemodels.LastUpdated(time.Now()),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusFAIL,
		Suppressed:     false,
	}

	// mock call to compliance-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(complianceResponse, http.StatusOK), nil).Once()

	require.NoError(t, Handle(input))

	// Verifying request to fetch compliance information
	httpRequest := mockRoundTripper.Calls[0].Arguments[0].(*http.Request)
	assert.Equal(t, "policyId=test-policy&resourceId=test-resource", httpRequest.URL.RawQuery)

	mockDdbClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestSkipActionsIfResourceIsNotFailing(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	input := &models.ComplianceNotification{
		ResourceID:      aws.String("test-resource"),
		PolicyID:        aws.String("test-policy"),
		PolicyVersionID: aws.String("test-version"),
		ShouldAlert:     aws.Bool(true),
	}

	responseBody := &compliancemodels.ComplianceStatus{
		LastUpdated:    compliancemodels.LastUpdated(time.Now()),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusPASS,
		Suppressed:     false,
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(responseBody, http.StatusOK), nil)

	require.NoError(t, Handle(input))
	mockDdbClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestSkipActionsIfLookupFailed(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	input := &models.ComplianceNotification{
		ResourceID:  aws.String("test-resource"),
		PolicyID:    aws.String("test-policy"),
		ShouldAlert: aws.Bool(true),
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse("", http.StatusInternalServerError), nil)

	require.Error(t, Handle(input))
	mockDdbClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func generateResponse(body interface{}, httpCode int) *http.Response {
	serializedBody, _ := jsoniter.MarshalToString(body)
	return &http.Response{StatusCode: httpCode, Body: ioutil.NopCloser(strings.NewReader(serializedBody))}
}
