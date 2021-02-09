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
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// CreatePolicy adds a new policy to the Dynamo table.
func (API) CreatePolicy(input *models.CreatePolicyInput) *events.APIGatewayProxyResponse {
	return writePolicy(input, true)
}

func (API) UpdatePolicy(input *models.UpdatePolicyInput) *events.APIGatewayProxyResponse {
	return writePolicy(input, false)
}

// Shared by CreatePolicy and UpdatePolicy
func writePolicy(input *models.CreatePolicyInput, create bool) *events.APIGatewayProxyResponse {
	if err := validateUpdatePolicy(input); err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       err.Error(),
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
		return &events.APIGatewayProxyResponse{
			Body:       "cannot save an enabled policy with failing unit tests",
			StatusCode: http.StatusBadRequest,
		}
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
		Reports:                   input.Reports,
		ResourceTypes:             input.ResourceTypes,
		Runbook:                   input.Runbook,
		Severity:                  input.Severity,
		Suppressions:              input.Suppressions,
		Tags:                      input.Tags,
		Tests:                     input.Tests,
		Type:                      models.TypePolicy,
	}

	var status compliancemodels.ComplianceStatus
	var statusCode int

	if create {
		// create new policy - no entry with that ID should exist
		if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
			if err == errExists {
				return &events.APIGatewayProxyResponse{
					Body:       err.Error(),
					StatusCode: http.StatusConflict,
				}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}

		// New policies are "passing" since they haven't evaluated anything yet.
		status = compliancemodels.StatusPass
		statusCode = http.StatusCreated
	} else {
		// update existing policy - entry must already exist
		if _, err := writeItem(item, input.UserID, aws.Bool(true)); err != nil {
			if err == errNotExists || err == errWrongType {
				// errWrongType means we tried to modify a policy that is actually a rule.
				// In this case return 404 - the policy you tried to modify does not exist.
				return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}

		statusStruct, err := getComplianceStatus(input.ID)
		if err != nil {
			return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		status = statusStruct.Status
		statusCode = http.StatusOK
	}

	return gatewayapi.MarshalResponse(item.Policy(status), statusCode)
}

// Some extra validation which is not implemented in the input struct tags
func validateUpdatePolicy(input *models.CreatePolicyInput) error {
	if err := validResourceTypeSet(input.ResourceTypes); err != nil {
		return errors.Errorf("policy contains invalid resource type: %s", err.Error())
	}
	return nil
}

// enabledPolicyTestsPass returns false if the policy is enabled and its tests fail.
func enabledPolicyTestsPass(policy *models.UpdatePolicyInput) (bool, error) {
	if !policy.Enabled || len(policy.Tests) == 0 {
		return true, nil
	}

	testResults, err := policyEngine.TestPolicy(&models.TestPolicyInput{
		Body:          policy.Body,
		ResourceTypes: policy.ResourceTypes,
		Tests:         policy.Tests,
	})
	if err != nil {
		return false, err
	}

	for _, result := range testResults.Results {
		if !result.Passed {
			return false, nil
		}
	}
	return true, nil
}
