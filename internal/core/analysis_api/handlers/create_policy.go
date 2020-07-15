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
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// CreatePolicy adds a new policy to the Dynamo table.
func CreatePolicy(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseUpdatePolicy(request)
	if err != nil {
		return badRequest(err)
	}

	// Disallow saving if policy is enabled and its tests fail.
	ok, err := enabledPolicyTestsPass(input)
	if err != nil {
		return failedRequest(err.Error(), http.StatusInternalServerError)
	}
	if !ok {
		return badRequest(errPolicyTestsFail)
	}

	item := &tableItem{
		AutoRemediationID:         input.AutoRemediationID,
		AutoRemediationParameters: input.AutoRemediationParameters,
		Body:                      input.Body,
		Description:               input.Description,
		DisplayName:               input.DisplayName,
		Enabled:                   input.Enabled,
		ID:                        input.ID,
		OutputIds:                 input.OutputIds,
		Reference:                 input.Reference,
		ResourceTypes:             input.ResourceTypes,
		Runbook:                   input.Runbook,
		Severity:                  input.Severity,
		Suppressions:              input.Suppressions,
		Tags:                      input.Tags,
		Tests:                     input.Tests,
		Type:                      typePolicy,
	}

	if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
		if err == errExists {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusConflict}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// New policies are "passing" since they haven't evaluated anything yet.
	return gatewayapi.MarshalResponse(item.Policy(models.ComplianceStatusPASS), http.StatusCreated)
}

// body parsing shared by CreatePolicy and ModifyPolicy
func parseUpdatePolicy(request *events.APIGatewayProxyRequest) (*models.UpdatePolicy, error) {
	var result models.UpdatePolicy
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	if err := result.Validate(nil); err != nil {
		return nil, err
	}

	// Policy names are embedded in emails, alert outputs, etc. Prevent a possible injection attack
	if genericapi.ContainsHTML(string(result.DisplayName)) {
		return nil, fmt.Errorf("display name: %v", genericapi.ErrContainsHTML)
	}

	return &result, nil
}

var errPolicyTestsFail = errors.New("cannot save an enabled policy with failing unit tests")

// enabledPolicyTestsPass returns false if the policy is enabled and its tests fail.
func enabledPolicyTestsPass(policy *models.UpdatePolicy) (bool, error) {
	if !policy.Enabled || len(policy.Tests) == 0 {
		return true, nil
	}
	testResults, err := policyEngine.TestPolicy(toTestPolicy(policy))
	if err != nil {
		return false, err
	}
	return bool(testResults.TestSummary), nil
}

func toTestPolicy(updatePolicy *models.UpdatePolicy) *models.TestPolicy {
	return &models.TestPolicy{
		AnalysisType:  models.AnalysisTypePOLICY,
		Body:          updatePolicy.Body,
		ResourceTypes: updatePolicy.ResourceTypes,
		Tests:         updatePolicy.Tests,
	}
}
