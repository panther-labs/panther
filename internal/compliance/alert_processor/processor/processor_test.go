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
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	analysismodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	remediationmodels "github.com/panther-labs/panther/api/lambda/remediation/models"
	"github.com/panther-labs/panther/internal/compliance/alert_processor/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
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

	mockComplianceClient := &gatewayapi.MockClient{}
	complianceClient = mockComplianceClient

	mockRemediationClient := &gatewayapi.MockClient{}
	remediationClient = mockRemediationClient

	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	input := &models.ComplianceNotification{
		ResourceID:      "test-resource",
		PolicyID:        "test-policy",
		PolicyVersionID: "test-version",
		ShouldAlert:     true,
		Timestamp:       time.Now(),
	}

	complianceResponse := &compliancemodels.ComplianceEntry{
		LastUpdated:    time.Now(),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusFail,
		Suppressed:     false,
	}

	policyResponse := &analysismodels.Policy{
		AutoRemediationID: "test-autoremediation-id",
	}

	// mock call to compliance-api
	complianceInput := &compliancemodels.LambdaInput{
		GetStatus: &compliancemodels.GetStatusInput{PolicyID: "test-policy", ResourceID: "test-resource"},
	}
	mockComplianceClient.On("Invoke", complianceInput, mock.Anything).Return(
		http.StatusOK, nil, complianceResponse)

	// mock call to analysis-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(policyResponse, http.StatusOK), nil).Once()

	// mock call to remediate-api
	remediationInput := &remediationmodels.LambdaInput{
		RemediateResourceAsync: &remediationmodels.RemediateResourceAsyncInput{
			PolicyID:   "test-policy",
			ResourceID: "test-resource",
		},
	}
	mockRemediationClient.On("Invoke", remediationInput, nil).Return(http.StatusOK, nil, nil)

	mockDdbClient.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, nil)

	require.NoError(t, Handle(input))

	mockComplianceClient.AssertExpectations(t)
	mockRemediationClient.AssertExpectations(t)
	mockDdbClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleEventWithAlertButNoAutoRemediationID(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockComplianceClient := &gatewayapi.MockClient{}
	complianceClient = mockComplianceClient
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	input := &models.ComplianceNotification{
		ResourceID:      "test-resource",
		PolicyID:        "test-policy",
		PolicyVersionID: "test-version",
		ShouldAlert:     true,
		Timestamp:       time.Now(),
	}

	complianceResponse := &compliancemodels.ComplianceEntry{
		LastUpdated:    time.Now(),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusFail,
		Suppressed:     false,
	}

	policyResponse := &analysismodels.Policy{} // no AutoRemediationID

	// mock call to compliance-api
	complianceInput := &compliancemodels.LambdaInput{
		GetStatus: &compliancemodels.GetStatusInput{PolicyID: "test-policy", ResourceID: "test-resource"},
	}
	mockComplianceClient.On("Invoke", complianceInput, mock.Anything).Return(
		http.StatusOK, nil, complianceResponse)

	// mock call to analysis-api
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(policyResponse, http.StatusOK), nil).Once()
	// should NOT call remediation api!

	mockDdbClient.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, nil)

	require.NoError(t, Handle(input))

	mockComplianceClient.AssertExpectations(t)
	mockDdbClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestHandleEventWithoutAlert(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockComplianceClient := &gatewayapi.MockClient{}
	complianceClient = mockComplianceClient

	input := &models.ComplianceNotification{
		ResourceID:      "test-resource",
		PolicyID:        "test-policy",
		PolicyVersionID: "test-version",
		ShouldAlert:     false,
	}

	complianceResponse := &compliancemodels.ComplianceEntry{
		LastUpdated:    time.Now(),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusFail,
		Suppressed:     false,
	}

	// mock call to compliance-api
	complianceInput := &compliancemodels.LambdaInput{
		GetStatus: &compliancemodels.GetStatusInput{PolicyID: "test-policy", ResourceID: "test-resource"},
	}
	mockComplianceClient.On("Invoke", complianceInput, mock.Anything).Return(
		http.StatusOK, nil, complianceResponse)
	require.NoError(t, Handle(input))

	mockComplianceClient.AssertExpectations(t)
	mockDdbClient.AssertExpectations(t)
}

func TestSkipActionsIfResourceIsNotFailing(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockComplianceClient := &gatewayapi.MockClient{}
	complianceClient = mockComplianceClient

	input := &models.ComplianceNotification{
		ResourceID:      "test-resource",
		PolicyID:        "test-policy",
		PolicyVersionID: "test-version",
		ShouldAlert:     true,
	}

	responseBody := &compliancemodels.ComplianceEntry{
		LastUpdated:    time.Now(),
		PolicyID:       "test-policy",
		PolicySeverity: "INFO",
		ResourceID:     "test-resource",
		ResourceType:   "AWS.S3.Test",
		Status:         compliancemodels.StatusPass,
		Suppressed:     false,
	}

	// mock call to compliance-api
	complianceInput := &compliancemodels.LambdaInput{
		GetStatus: &compliancemodels.GetStatusInput{PolicyID: "test-policy", ResourceID: "test-resource"},
	}
	mockComplianceClient.On("Invoke", complianceInput, mock.Anything).Return(
		http.StatusOK, nil, responseBody)

	require.NoError(t, Handle(input))
	mockComplianceClient.AssertExpectations(t)
	mockDdbClient.AssertExpectations(t)
}

func TestSkipActionsIfLookupFailed(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockComplianceClient := &gatewayapi.MockClient{}
	complianceClient = mockComplianceClient

	input := &models.ComplianceNotification{
		ResourceID:  "test-resource",
		PolicyID:    "test-policy",
		ShouldAlert: true,
	}

	// mock call to compliance-api
	complianceInput := &compliancemodels.LambdaInput{
		GetStatus: &compliancemodels.GetStatusInput{PolicyID: "test-policy", ResourceID: "test-resource"},
	}
	mockComplianceClient.On("Invoke", complianceInput, mock.Anything).Return(
		http.StatusInternalServerError, fmt.Errorf("internal error"), nil)

	require.Error(t, Handle(input))
	mockComplianceClient.AssertExpectations(t)
	mockDdbClient.AssertExpectations(t)
}

func generateResponse(body interface{}, httpCode int) *http.Response {
	serializedBody, _ := jsoniter.MarshalToString(body)
	return &http.Response{StatusCode: httpCode, Body: ioutil.NopCloser(strings.NewReader(serializedBody))}
}
