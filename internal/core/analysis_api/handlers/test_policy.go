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
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	enginemodels "github.com/panther-labs/panther/api/gateway/analysis"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	testPolicyID   = "PolicyApiTestingPolicy"
	testResourceID = "Panther:Test:Resource:"
)

// TestPolicy runs a policy against a set of unit tests.
//
// TODO - test policies before enabling them
func TestPolicy(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseTestPolicy(request)
	if err != nil {
		return badRequest(err)
	}

	var results *enginemodels.PolicyEngineOutput
	// Build the policy engine request
	if input.AnalysisType == models.AnalysisTypeRULE {
		ruleResults, errResponse := getRuleResults(input)
		if errResponse != nil {
			return errResponse
		}
		results = &enginemodels.PolicyEngineOutput{
			Resources: make([]enginemodels.Result, 0, len(ruleResults.Events)),
		}
		for _, event := range ruleResults.Events {
			results.Resources = append(results.Resources, enginemodels.Result{
				ID:      event.ID,
				Errored: event.Errored,
				// Note: These are flipped from what would be expected due to the fact that a
				// 'True' return and a 'False' return have different meanings for polices vs. rules
				Failed: event.NotMatched,
				Passed: event.Matched,
			})
		}
	} else {
		var errResponse *events.APIGatewayProxyResponse
		results, errResponse = getPolicyResults(input)
		if errResponse != nil {
			return errResponse
		}
	}

	// Determine the results of the tests
	var testResults = models.TestPolicyResult{
		TestSummary: true,
		// initialize as empty slices (not null) so they serialize correctly
		TestsErrored: models.TestsErrored{},
		TestsFailed:  models.TestsFailed{},
		TestsPassed:  models.TestsPassed{},
	}

	for _, result := range results.Resources {
		// Determine which test case this result corresponds to. We constructed resourceID with the
		// format Panther:Test:Resource:TestNumber
		testIndex, err := strconv.Atoi(strings.Split(result.ID, ":")[3])
		if err != nil {
			// We constructed this resourceID, if it is not in the expected format it has been
			// mangled by us somehow
			zap.L().Error("unable to extract test number from test result resourceID",
				zap.String("resourceID", result.ID))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		test := input.Tests[testIndex]
		switch {
		case len(result.Errored) > 0:
			// There was an error running this test, store the error message
			testResults.TestsErrored = append(testResults.TestsErrored, &models.TestErrorResult{
				ErrorMessage: result.Errored[0].Message,
				Name:         string(test.Name),
			})
			testResults.TestSummary = false

		case len(result.Failed) > 0 && bool(test.ExpectedResult), len(result.Passed) > 0 && !bool(test.ExpectedResult):
			// The test result was not expected, so this test failed
			testResults.TestsFailed = append(testResults.TestsFailed, string(test.Name))
			testResults.TestSummary = false

		case len(result.Failed) > 0 && !bool(test.ExpectedResult), len(result.Passed) > 0 && bool(test.ExpectedResult):
			// The test result was as expected
			testResults.TestsPassed = append(testResults.TestsPassed, string(test.Name))

		default:
			// This test didn't run (result.{Errored, Failed, Passed} are all empty). This must not happen absent a bug.
			zap.L().Error("unable to run test for resourceID", zap.String("resourceID", result.ID))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
	}

	// Return the number of passing, failing, and error-ing tests
	return gatewayapi.MarshalResponse(&testResults, http.StatusOK)
}

//nolint:dupl
func getRuleResults(input *models.TestPolicy) (*enginemodels.RulesEngineOutput, *events.APIGatewayProxyResponse) {
	// Build the list of events to run the rule against
	inputEvents := make([]enginemodels.Event, len(input.Tests))
	for i, test := range input.Tests {
		// Unmarshal event into object form
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(test.Resource), &attrs); err != nil {
			return nil, badRequest(errors.Wrapf(err, "tests[%d].event is not valid json", i))
		}

		inputEvents[i] = enginemodels.Event{
			Data: attrs,
			ID:   testResourceID + strconv.Itoa(i),
		}
	}

	testRequest := enginemodels.RulesEngineInput{
		Rules: []enginemodels.Rule{
			{
				Body: string(input.Body),
				// Doesn't matter as we're only running one rule
				ID:       testPolicyID,
				LogTypes: input.ResourceTypes,
			},
		},
		Events: inputEvents,
	}

	// Send the request to the rule-engine
	var rulesEngineResults *enginemodels.RulesEngineOutput
	payload, err := jsoniter.Marshal(&testRequest)
	if err != nil {
		zap.L().Error("failed to marshal RuleEngineInput", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	response, err := lambdaClient.Invoke(&lambda.InvokeInput{FunctionName: &env.RulesEngine, Payload: payload})

	// Handle invocation failures and lambda errors
	if err != nil || response.FunctionError != nil {
		zap.L().Error("error while invoking rules-engine lambda", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := jsoniter.Unmarshal(response.Payload, &rulesEngineResults); err != nil {
		zap.L().Error("failed to unmarshal lambda response into RuleEngineOutput", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return rulesEngineResults, nil
}

//nolint:dupl
func getPolicyResults(input *models.TestPolicy) (*enginemodels.PolicyEngineOutput, *events.APIGatewayProxyResponse) {
	// Build the list of resources to run the policy against
	resources := make([]enginemodels.Resource, len(input.Tests))
	for i, test := range input.Tests {
		// Unmarshal resource into object form
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(test.Resource), &attrs); err != nil {
			return nil, badRequest(errors.Wrapf(err, "tests[%d].resource is not valid json", i))
		}

		resources[i] = enginemodels.Resource{
			Attributes: attrs,
			ID:         testResourceID + strconv.Itoa(i),
			Type:       policyTestType(input),
		}
	}

	testRequest := enginemodels.PolicyEngineInput{
		Policies: []enginemodels.Policy{
			{
				Body: string(input.Body),
				// Doesn't matter as we're only running one policy
				ID:            testPolicyID,
				ResourceTypes: input.ResourceTypes,
			},
		},
		Resources: resources,
	}

	// Send the request to the policy-engine
	var policyEngineResults *enginemodels.PolicyEngineOutput
	payload, err := jsoniter.Marshal(&testRequest)
	if err != nil {
		zap.L().Error("failed to marshal PolicyEngineInput", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	response, err := lambdaClient.Invoke(&lambda.InvokeInput{FunctionName: &env.PolicyEngine, Payload: payload})

	// Handle invocation failures and lambda errors
	if err != nil || response.FunctionError != nil {
		zap.L().Error("error while invoking policy-engine lambda", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := jsoniter.Unmarshal(response.Payload, &policyEngineResults); err != nil {
		zap.L().Error("failed to unmarshal lambda response into PolicyEngineOutput", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return policyEngineResults, nil
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

// policyTestType returns the resource type to use as the input to the policy engine.
// The engine picks the policy to run based on the input resource type. To make the engine run the
// input policy, we just pass one of its resource types in the input resource.
// If the policy is applicable for all resource types, a placeholder value is returned since the engine will
// run it for any resource type input.
func policyTestType(input *models.TestPolicy) string {
	if len(input.ResourceTypes) > 0 {
		return input.ResourceTypes[0]
	}
	return "__ALL__"
}
