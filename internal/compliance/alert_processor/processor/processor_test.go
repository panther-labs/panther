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
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-playground/assert.v1"

	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	remediationmodels "github.com/panther-labs/panther/api/lambda/remediation/models"
	"github.com/panther-labs/panther/internal/compliance/alert_processor/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

var timeNow = time.Unix(1581379785, 0).UTC() // Set a static time

func genSampleEvent() *models.ComplianceNotification {
	return &models.ComplianceNotification{
		ResourceID:      "arn:aws:iam::xxx...",
		PolicyID:        "Test.Policy",
		PolicyVersionID: "A policy version",
		ShouldAlert:     true,
		Timestamp:       timeNow,
	}
}

func TestHandleEventWithAlert(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient

	mockPolicyClient := &gatewayapi.MockClient{}
	policyClient = mockPolicyClient
	mockComplianceClient := &gatewayapi.MockClient{}
	complianceClient = mockComplianceClient
	mockRemediationClient := &gatewayapi.MockClient{}
	remediationClient = mockRemediationClient

	input := &models.ComplianceNotification{
		ResourceID:      "test-resource",
		PolicyID:        "test-policy",
		PolicyVersionID: "test-version",
		ShouldAlert:     true,
		Timestamp:       time.Now().UTC(),
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
	getPolicyInput := &analysismodels.LambdaInput{
		GetPolicy: &analysismodels.GetPolicyInput{ID: "test-policy"},
	}
	mockPolicyClient.On("Invoke", getPolicyInput, mock.Anything).Return(
		http.StatusOK, nil, policyResponse).Once()

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
	mockPolicyClient.AssertExpectations(t)
	mockRemediationClient.AssertExpectations(t)
	mockDdbClient.AssertExpectations(t)
}

func TestHandleEventWithAlertButNoAutoRemediationID(t *testing.T) {
	mockDdbClient := &testutils.DynamoDBMock{}
	ddbClient = mockDdbClient
	mockComplianceClient := &gatewayapi.MockClient{}
	complianceClient = mockComplianceClient
	mockPolicyClient := &gatewayapi.MockClient{}
	policyClient = mockPolicyClient

	input := &models.ComplianceNotification{
		ResourceID:      "test-resource",
		PolicyID:        "test-policy",
		PolicyVersionID: "test-version",
		ShouldAlert:     true,
		Timestamp:       time.Now().UTC(),
	}

	complianceResponse := &compliancemodels.ComplianceEntry{
		LastUpdated:    time.Now().UTC(),
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
	getPolicyInput := &analysismodels.LambdaInput{
		GetPolicy: &analysismodels.GetPolicyInput{ID: "test-policy"},
	}
	mockPolicyClient.On("Invoke", getPolicyInput, mock.Anything).Return(
		http.StatusOK, nil, policyResponse).Once()
	// should NOT call remediation api!

	mockDdbClient.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, nil)

	require.NoError(t, Handle(input))

	mockComplianceClient.AssertExpectations(t)
	mockPolicyClient.AssertExpectations(t)
	mockDdbClient.AssertExpectations(t)
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
		LastUpdated:    time.Now().UTC(),
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
		LastUpdated:    time.Now().UTC(),
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

func TestGenerateAlertID(t *testing.T) {
	event := genSampleEvent()
	eventID := GenerateAlertID(event)
	assert.Equal(t, *eventID, "26df596024d2e81140de028387d517da")
}
