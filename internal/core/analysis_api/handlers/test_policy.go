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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// TestPolicy runs a policy (or rule) against a set of unit tests.
func TestPolicy(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseTestPolicy(request)
	if err != nil {
		return badRequest(err)
	}

	var testResults models.TestPolicyResult
	if input.AnalysisType == models.AnalysisTypeRULE {
		testResults, err = ruleEngine.TestRule(input)
	} else {
		testResults, err = policyEngine.TestPolicy(input)
	}
	if err != nil {
		return failedRequest(err.Error(), http.StatusInternalServerError)
	}

	return gatewayapi.MarshalResponse(&testResults, http.StatusOK)
}

func parseTestPolicy(request *events.APIGatewayProxyRequest) (*models.TestPolicy, error) {
	var result models.TestPolicy
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	if err := result.Validate(nil); err != nil {
		return nil, err
	}

	return &result, nil
}
