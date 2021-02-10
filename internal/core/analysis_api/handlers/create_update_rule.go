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
	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	// Default Deduplication period for rules
	defaultDedupPeriodMinutes = 60
	// Default Threshold value for Rules
	defaultRuleThreshold = 1
)

func (API) CreateRule(input *models.CreateRuleInput) *events.APIGatewayProxyResponse {
	return writeRule(input, true)
}

func (API) UpdateRule(input *models.UpdateRuleInput) *events.APIGatewayProxyResponse {
	return writeRule(input, false)
}

// Shared by CreateRule and UpdateRule
func writeRule(input *models.CreateRuleInput, create bool) *events.APIGatewayProxyResponse {
	if err := validateUpdateRule(input); err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       err.Error(),
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
		return &events.APIGatewayProxyResponse{
			Body:       "cannot save an enabled rule with failing unit tests",
			StatusCode: http.StatusBadRequest,
		}
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
		Reports:            input.Reports,
		ResourceTypes:      input.LogTypes,
		Runbook:            input.Runbook,
		Severity:           input.Severity,
		Tags:               input.Tags,
		Tests:              input.Tests,
		Type:               models.TypeRule,
	}

	var statusCode int

	if create {
		if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
			if err == errExists {
				return &events.APIGatewayProxyResponse{
					Body:       err.Error(),
					StatusCode: http.StatusConflict,
				}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		statusCode = http.StatusCreated
	} else {
		if _, err := writeItem(item, input.UserID, aws.Bool(true)); err != nil {
			if err == errNotExists || err == errWrongType {
				// errWrongType means we tried to modify a rule which is actually a policy.
				// In this case return 404 - the rule you tried to modify does not exist.
				return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		statusCode = http.StatusOK
	}

	return gatewayapi.MarshalResponse(item.Rule(), statusCode)
}

// Some extra validation which is not implemented in the input struct tags
func validateUpdateRule(input *models.CreateRuleInput) error {
	if err := validateLogtypeSet(input.LogTypes); err != nil {
		return errors.Errorf("rule contains invalid log type: %s", err.Error())
	}
	return nil
}

// enabledRuleTestsPass returns false if the rule is enabled and its tests fail.
func enabledRuleTestsPass(rule *models.UpdateRuleInput) (bool, error) {
	if !rule.Enabled || len(rule.Tests) == 0 {
		return true, nil
	}

	testResults, err := ruleEngine.TestRule(&models.TestRuleInput{
		Body:     rule.Body,
		LogTypes: rule.LogTypes,
		Tests:    rule.Tests,
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
