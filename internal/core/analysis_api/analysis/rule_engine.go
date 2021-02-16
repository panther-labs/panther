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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	enginemodels "github.com/panther-labs/panther/api/lambda/analysis"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
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

func (e *RuleEngine) TestRule(rule *models.TestRuleInput) (*models.TestRuleOutput, error) {
	// Build the list of events to run the rule against
	inputEvents := make([]enginemodels.Event, len(rule.Tests))
	for i, test := range rule.Tests {
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(test.Resource, &attrs); err != nil {
			//nolint // Error is capitalized because will be returned to the UI
			return nil, &TestInputError{fmt.Errorf(`Event for test "%s" is not valid json: %w`, test.Name, err)}
		}

		var mocks map[string]string
		if test.Mocks != "" {
			if err := jsoniter.UnmarshalFromString(test.Mocks, &mocks); err != nil {
				//nolint // Error is capitalized because will be returned to the UI
				return nil, &TestInputError{fmt.Errorf(`Mocks for test "%s" event "%d" is not valid json: %w`, test.Name, i, err)}
			}
		}

		inputEvents[i] = enginemodels.Event{
			Data:  attrs,
			ID:    strconv.Itoa(i),
			Mocks: mocks,
		}
	}

	input := enginemodels.RulesEngineInput{
		Rules: []enginemodels.Rule{
			{
				Body:     rule.Body,
				ID:       testRuleID, // doesn't matter as we're only running one rule
				LogTypes: rule.LogTypes,
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
	testResult := &models.TestRuleOutput{
		Results: make([]models.TestRuleRecord, len(engineOutput.Results)),
	}
	for i, result := range engineOutput.Results {
		// Determine which test case this result corresponds to.
		testIndex, err := strconv.Atoi(result.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to extract test number from test result resourceID %s", result.ID)
		}
		test := rule.Tests[testIndex]

		record := models.TestRuleRecord{
			ID:     result.ID,
			Name:   test.Name,
			Passed: hasPassed(test.ExpectedResult, result),
			Functions: models.TestRuleRecordFunctions{
				Rule: buildTestSubRecord(strconv.FormatBool(result.RuleOutput), result.RuleError),
			},
		}
		if result.GenericError != "" {
			record.Error = &models.TestError{Message: result.GenericError}
		}

		// The remaining functions are only included if the user expects rule() to match the event
		if test.ExpectedResult {
			record.Functions.Title = buildTestSubRecord(result.TitleOutput, result.TitleError)
			record.Functions.Dedup = buildTestSubRecord(result.DedupOutput, result.DedupError)
			record.Functions.AlertContext = buildTestSubRecord(truncate(result.AlertContextOutput), result.AlertContextError)
			// Show the output of other functions only if user expects rule() to match the event (ie return True).
			record.Functions.Description = buildTestSubRecord(result.DescriptionOutput, result.DescriptionError)
			record.Functions.Reference = buildTestSubRecord(result.ReferenceOutput, result.ReferenceError)
			record.Functions.Severity = buildTestSubRecord(result.SeverityOutput, result.SeverityError)
			record.Functions.Runbook = buildTestSubRecord(result.RunbookOutput, result.RunbookError)
			record.Functions.Destinations = buildTestSubRecordList(result.DestinationsOutput, result.DestinationsError)
		}

		testResult.Results[i] = record
	}
	return testResult, nil
}

func buildTestSubRecord(output, error string) *models.TestDetectionSubRecord {
	if output == "" && error == "" {
		return nil
	}

	result := &models.TestDetectionSubRecord{}
	if output != "" {
		result.Output = &output
	}
	if error != "" {
		result.Error = &models.TestError{Message: error}
	}
	return result
}

func buildTestSubRecordList(output []string, error string) *models.TestDetectionSubRecord {
	if len(output) == 0 && error == "" {
		return nil
	}

	result := &models.TestDetectionSubRecord{}

	if len(output) != 0 {
		result.Output = aws.String(strings.Join(output, ", "))
	}
	if error != "" {
		result.Error = &models.TestError{Message: error}
	}
	return result
}

func truncate(s string) string {
	maxChars := 140
	if len(s) > maxChars {
		return s[:maxChars] + "..."
	}
	return s
}

func hasPassed(expectedRuleOutput bool, result enginemodels.RuleResult) bool {
	if len(result.GenericError) > 0 || len(result.RuleError) > 0 {
		// If there is an error in the script functions, like import/syntax/indentation error or rule() raised
		// an exception, fail the test.
		return false
	}
	if !expectedRuleOutput {
		// rule() should return false (not match the event), so the other functions (title/dedup etc) should not
		// affect the test result.
		return result.RuleOutput == expectedRuleOutput
	}

	// rule() should return True. We also expect the other functions to not raise any exceptions.
	return !result.Errored && (result.RuleOutput == expectedRuleOutput)
}

const testRuleID = "RuleAPITestRule"
