package handlers

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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// CreatePolicy adds a new policy to the Dynamo table.
func (API) CreatePolicy(input *models.CreatePolicyInput) *events.APIGatewayProxyResponse {
	// Policy names are embedded in emails, alert outputs, etc. Prevent a possible injection attack
	if genericapi.ContainsHTML(input.DisplayName) {
		return &events.APIGatewayProxyResponse{
			Body:       "invalid display name: " + genericapi.ErrContainsHTML.Error(),
			StatusCode: http.StatusBadRequest,
		}
	}

	// Disallow saving if policy is enabled and its tests fail.
	testsPass, err := enabledPolicyTestsPass(input)

	if err != nil {
		statusCode := http.StatusInternalServerError
		if _, ok := err.(*analysis.TestInputError); ok {
			statusCode = http.StatusBadRequest
		}
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: statusCode}
	}
	if !testsPass {
		return &events.APIGatewayProxyResponse{Body: errPolicyTestsFail.Error(), StatusCode: http.StatusBadRequest}
	}

	item := &tableItem{
		AutoRemediationID:         input.AutoRemediationID,
		AutoRemediationParameters: input.AutoRemediationParameters,
		Body:                      input.Body,
		Description:               input.Description,
		DisplayName:               input.DisplayName,
		Enabled:                   input.Enabled,
		ID:                        input.ID,
		OutputIDs:                 input.OutputIDs,
		Reference:                 input.Reference,
		ResourceTypes:             input.ResourceTypes,
		Runbook:                   input.Runbook,
		Severity:                  input.Severity,
		Suppressions:              input.Suppressions,
		Tags:                      input.Tags,
		Tests:                     input.Tests,
		Type:                      models.TypePolicy,
	}

	if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
		if err == errExists {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusConflict}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// New policies are "passing" since they haven't evaluated anything yet.
	return gatewayapi.MarshalResponse(item.Policy(compliancemodels.StatusPass), http.StatusCreated)
}

var errPolicyTestsFail = errors.New("cannot save an enabled policy with failing unit tests")

// enabledPolicyTestsPass returns false if the policy is enabled and its tests fail.
func enabledPolicyTestsPass(policy *models.UpdatePolicyInput) (bool, error) {
	if !policy.Enabled || len(policy.Tests) == 0 {
		return true, nil
	}
	testResults, err := policyEngine.TestPolicy(toTestPolicy(policy))
	if err != nil {
		return false, err
	}
	return testResults.TestSummary, nil
}

func toTestPolicy(updatePolicy *models.UpdatePolicyInput) *models.TestPolicyInput {
	return &models.TestPolicyInput{
		AnalysisType:  models.TypePolicy,
		Body:          updatePolicy.Body,
		ResourceTypes: updatePolicy.ResourceTypes,
		Tests:         updatePolicy.Tests,
	}
}
