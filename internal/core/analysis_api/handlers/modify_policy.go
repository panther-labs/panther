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

	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// ModifyPolicy updates an existing policy.
func ModifyPolicy(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
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

	if _, err := writeItem(item, input.UserID, aws.Bool(true)); err != nil {
		if err == errNotExists || err == errWrongType {
			// errWrongType means we tried to modify a policy that is actually a rule.
			// In this case return 404 - the policy you tried to modify does not exist.
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	status, err := getComplianceStatus(input.ID)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(item.Policy(status.Status), http.StatusOK)
}
