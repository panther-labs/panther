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
		TestSummary: true,
		Results:     make([]*models.RuleResult, len(engineOutput.Results)),
	}
	for i, result := range engineOutput.Results {
		// Determine which test case this result corresponds to.
		testIndex, err := strconv.Atoi(result.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to extract test number from test result resourceID %s", result.ID)
		}
		test := rule.Tests[testIndex]

		// The test is considered failed iff:
		// - there is a global error in the rule script (import error, syntax error, etc).
		// - rule() raises an exception.
		// - rule() return value is different than the expected value user provided.
		// Otherwise the test is considered passed.
		//
		// If the other functions (title/dedup/alert_context etc) raise an exception, it has no
		// effect on the test outcome, because:
		// 1. Users can provide unit tests for the rule() function only,
		// 2. It most intuitive. Consider the following scenario:
		//	- User creates a test case where the input is missing some fields and expects rule() to return False.
		//	- title() fails with KeyError or similar because it uses a field that is missing from the test input.
		// The test should be successful, because rule() returns False as the user expects.
		// This is also consistent with log analysis, where if rule won't trigger the alert, the other functions
		// are not run.
		var passed bool
		if len(result.GenericError) > 0 || len(result.RuleError) > 0 {
			passed = false
		} else {
			passed = result.RuleOutput == bool(test.ExpectedResult)
		}

		testResult.Results[i] = &models.RuleResult{
			ID:                 result.ID,
			RuleID:             result.RuleID,
			TestName:           string(test.Name),
			Passed:             passed,
			Errored:            result.Errored,
			RuleOutput:         result.RuleOutput,
			RuleError:          result.RuleError,
			DedupOutput:        result.DedupOutput,
			DedupError:         result.DedupError,
			TitleOutput:        result.TitleOutput,
			TitleError:         result.TitleError,
			AlertContextOutput: result.AlertContextOutput,
			AlertContextError:  result.AlertContextError,
			GenericError:       result.GenericError,
		}
		testResult.TestSummary = testResult.TestSummary && passed
	}
	return testResult, nil
}

const testRuleID = "RuleAPITestRule"
