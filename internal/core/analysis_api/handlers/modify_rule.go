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

	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// ModifyRule updates an existing rule.
func ModifyRule(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseUpdateRule(request)
	if err != nil {
		return badRequest(err)
	}

	// Disallow saving if rule is enabled and its tests fail.
	testsPass, err := enabledRuleTestsPass(input)
	if _, ok := err.(*analysis.TestInputError); ok {
		return badRequest(err)
	}
	if err != nil {
		return failedRequest(err.Error(), http.StatusInternalServerError)
	}
	if !testsPass {
		return badRequest(errRuleTestsFail)
	}

	item := &tableItem{
		Body:               input.Body,
		DedupPeriodMinutes: input.DedupPeriodMinutes,
		Threshold:          input.Threshold,
		Description:        input.Description,
		DisplayName:        input.DisplayName,
		Enabled:            input.Enabled,
		ID:                 input.ID,
		OutputIDs:          input.OutputIds,
		Reference:          input.Reference,
		ResourceTypes:      input.LogTypes,
		Runbook:            input.Runbook,
		Severity:           input.Severity,
		Tags:               input.Tags,
		Tests:              input.Tests,
		Type:               typeRule,
	}

	if _, err := writeItem(item, input.UserID, aws.Bool(true)); err != nil {
		if err == errNotExists || err == errWrongType {
			// errWrongType means we tried to modify a rule which is actually a policy.
			// In this case return 404 - the rule you tried to modify does not exist.
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(item.Rule(), http.StatusOK)
}
