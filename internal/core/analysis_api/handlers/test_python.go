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

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) TestPolicy(input *models.TestPolicyInput) *events.APIGatewayProxyResponse {
	return testPython(policyEngine.TestPolicy(input))
}

func (API) TestRule(input *models.TestRuleInput) *events.APIGatewayProxyResponse {
	return testPython(ruleEngine.TestRule(input))
}

func testPython(result interface{}, err error) *events.APIGatewayProxyResponse {
	if err != nil {
		if _, ok := err.(*analysis.TestInputError); ok {
			return &events.APIGatewayProxyResponse{
				Body: err.Error(), StatusCode: http.StatusBadRequest}
		}
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}
