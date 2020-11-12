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
	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	// Default Deduplication period for rules
	defaultDedupPeriodMinutes = 60
	// Default Threshold value for Rules
	defaultRuleThreshold = 1
)

// CreateRule adds a new rule to the Dynamo table.
func (API) CreateRule(input *models.CreateRuleInput) *events.APIGatewayProxyResponse {
	// Rule names are embedded in emails, alert outputs, etc. Prevent a possible injection attack
	if genericapi.ContainsHTML(input.DisplayName) {
		return &events.APIGatewayProxyResponse{
			Body:       "invalid display name: " + genericapi.ErrContainsHTML.Error(),
			StatusCode: http.StatusBadRequest,
		}
	}

	// in case it is not set, put a default. Minimum value for DedupPeriodMinutes is 15, so 0 means it's not set
	if input.DedupPeriodMinutes == 0 {
		input.DedupPeriodMinutes = defaultDedupPeriodMinutes
	}

	// Disallow saving if rule is enabled and its tests fail.
	testsPass, err := enabledRuleTestsPass(input)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if _, ok := err.(*analysis.TestInputError); ok {
			statusCode = http.StatusBadRequest
		}
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: statusCode}
	}
	if !testsPass {
		return &events.APIGatewayProxyResponse{Body: errRuleTestsFail.Error(), StatusCode: http.StatusBadRequest}
	}

	item := &tableItem{
		Body:               input.Body,
		DedupPeriodMinutes: input.DedupPeriodMinutes,
		Threshold:          input.Threshold,
		Description:        input.Description,
		DisplayName:        input.DisplayName,
		Enabled:            input.Enabled,
		ID:                 input.ID,
		OutputIDs:          input.OutputIDs,
		Reference:          input.Reference,
		ResourceTypes:      input.LogTypes,
		Runbook:            input.Runbook,
		Severity:           input.Severity,
		Tags:               input.Tags,
		Tests:              input.Tests,
		Type:               models.TypeRule,
	}

	if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
		if err == errExists {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusConflict}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(item.Rule(), http.StatusCreated)
}

var errRuleTestsFail = errors.New("cannot save an enabled rule with failing unit tests")

// enabledRuleTestsPass returns false if the rule is enabled and its tests fail.
func enabledRuleTestsPass(rule *models.UpdateRuleInput) (bool, error) {
	if !rule.Enabled || len(rule.Tests) == 0 {
		return true, nil
	}

	tp := &models.TestPolicyInput{
		AnalysisType:  models.TypeRule,
		Body:          rule.Body,
		ResourceTypes: rule.LogTypes,
		Tests:         rule.Tests,
	}
	testResults, err := ruleEngine.TestRule(tp)
	if err != nil {
		return false, err
	}
	return testResults.TestSummary, nil
}
