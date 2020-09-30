package analysis

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
	"strconv"

	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	enginemodels "github.com/panther-labs/panther/api/gateway/analysis"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// RuleEngine is a proxy for the rule engine backend (currently another lambda function).
type RuleEngine struct {
	lambdaClient lambdaiface.LambdaAPI
	lambdaName   string
}

func NewRuleEngine(lambdaClient lambdaiface.LambdaAPI, lambdaName string) RuleEngine {
	return RuleEngine{
		lambdaClient: lambdaClient,
		lambdaName:   lambdaName,
	}
}

func (e *RuleEngine) TestRule(rule *models.TestPolicy) (*models.TestRuleResult, error) {
	// Build the list of events to run the rule against
	inputEvents := make([]enginemodels.Event, len(rule.Tests))
	for i, test := range rule.Tests {
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(test.Resource), &attrs); err != nil {
			//nolint // Error is capitalized because will be returned to the UI
			return nil, &TestInputError{fmt.Errorf(`Event for test "%s" is not valid json: %w`, test.Name, err)}
		}

		inputEvents[i] = enginemodels.Event{
			Data: attrs,
			ID:   strconv.Itoa(i),
		}
	}

	input := enginemodels.RulesEngineInput{
		Rules: []enginemodels.Rule{
			{
				Body:     string(rule.Body),
				ID:       testRuleID, // doesn't matter as we're only running one rule
				LogTypes: rule.ResourceTypes,
			},
		},
		Events: inputEvents,
	}

	// Send the request to the rule-engine
	var engineOutput enginemodels.RulesEngineOutput
	err := genericapi.Invoke(e.lambdaClient, e.lambdaName, &input, &engineOutput)
	if err != nil {
		return nil, errors.Wrap(err, "error invoking rule engine")
	}

	// Translate rule engine output to test results.
	testResult := &models.TestRuleResult{
		TestsErrored: models.TestsErrored{},
		TestsFailed:  models.TestsFailed{},
		TestsPassed:  []*models.RulePassResult{},
	}
	for _, result := range engineOutput.Results {
		// Determine which test case this result corresponds to.
		testIndex, err := strconv.Atoi(result.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to extract test number from test result resourceID %s", result.ID)
		}
		test := rule.Tests[testIndex]

		if result.Errored {
			testResult.TestsErrored = append(testResult.TestsErrored, &models.TestErrorResult{
				ErrorMessage: result.ErrorMessage,
				Name:         string(test.Name),
			})
		} else if (result.Matched && bool(test.ExpectedResult)) || (!result.Matched && !bool(test.ExpectedResult)) {
			testResult.TestsPassed = append(testResult.TestsPassed, &models.RulePassResult{
				DedupOutput:  result.DedupOutput,
				ErrorMessage: result.ErrorMessage,
				Errored:      result.Errored,
				ID:           result.ID,
				Matched:      result.Matched,
				RuleID:       result.RuleID,
				TitleOutput:  result.TitleOutput,
			})
		} else {
			testResult.TestsFailed = append(testResult.TestsFailed, string(test.Name))
		}
	}
	testResult.TestSummary = len(testResult.TestsFailed) == 0 && len(testResult.TestsErrored) == 0
	return testResult, nil
}

const testRuleID = "RuleAPITestRule"
