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
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	enginemodels "github.com/panther-labs/panther/api/gateway/analysis"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/pkg/errors"
	"strconv"
	"strings"
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

func (e *RuleEngine) TestRule(policy *models.TestPolicy) (models.TestPolicyResult, error) {
	testResults := models.TestPolicyResult{}

	// Build the list of events to run the rule against
	inputEvents := make([]enginemodels.Event, len(policy.Tests))
	for i, test := range policy.Tests {
		// TODO: Can swagger unmarshall this already?
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(test.Resource), &attrs); err != nil {
			return testResults, errors.Wrapf(err, "tests[%d].event is not valid json", i)
		}

		inputEvents[i] = enginemodels.Event{
			Data: attrs,
			ID:   testResourceID + strconv.Itoa(i),
		}
	}

	input := enginemodels.RulesEngineInput{
		Rules: []enginemodels.Rule{
			{
				Body:     string(policy.Body),
				ID:       testPolicyID, // doesn't matter as we're only running one rule
				LogTypes: policy.ResourceTypes,
			},
		},
		Events: inputEvents,
	}

	// Send the request to the rule-engine
	var engineOutput enginemodels.RulesEngineOutput
	err := genericapi.Invoke(e.lambdaClient, e.lambdaName, &input, &engineOutput)
	if err != nil {
		return testResults, errors.Wrap(err, "error invoking rule engine")
	}

	// Translate rule engine output to test results.
	for _, result := range engineOutput.Events {
		// Determine which test case this result corresponds to. We constructed resourceID with the
		// format Panther:Test:Resource:TestNumber (see testResourceID),
		testIndex, err := strconv.Atoi(strings.Split(result.ID, ":")[3])
		if err != nil {
			return testResults, errors.Wrapf(err, "unable to extract test number from test result resourceID %s", result.ID)
		}

		test := policy.Tests[testIndex]
		switch {
		case len(result.Errored) > 0:
			// There was an error running this test, store the error message
			testResults.TestsErrored = append(testResults.TestsErrored, &models.TestErrorResult{
				ErrorMessage: result.Errored[0].Message,
				Name:         string(test.Name),
			})
			testResults.TestSummary = false

		case len(result.NotMatched) > 0 && bool(test.ExpectedResult), len(result.Matched) > 0 && !bool(test.ExpectedResult):
			// The test result was not expected, so this test failed
			testResults.TestsFailed = append(testResults.TestsFailed, string(test.Name))
			testResults.TestSummary = false

		case len(result.NotMatched) > 0 && !bool(test.ExpectedResult), len(result.Matched) > 0 && bool(test.ExpectedResult):
			// The test result was as expected
			testResults.TestsPassed = append(testResults.TestsPassed, string(test.Name))
			testResults.TestSummary = true

		default:
			// This test didn't run (result.{Errored, NotMatched, Matched} are all empty). This must not happen absent a bug.
			return testResults, errors.Errorf("unable to run test for ruleID %s", result.ID)
		}
	}
	return testResults, nil
}
