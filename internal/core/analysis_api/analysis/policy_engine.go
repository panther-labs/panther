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
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	enginemodels "github.com/panther-labs/panther/api/gateway/analysis"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	testPolicyID   = "PolicyApiTestingPolicy"
	testResourceID = "Panther:Test:Resource:"
)

// PoliceEngine is a proxy for the policy engine backend (currently another lambda function).
type PolicyEngine struct {
	lambdaClient lambdaiface.LambdaAPI
	lambdaName   string
}

func NewPolicyEngine(lambdaClient lambdaiface.LambdaAPI, lambdaName string) PolicyEngine {
	return PolicyEngine{
		lambdaClient: lambdaClient,
		lambdaName:   lambdaName,
	}
}

func (e *PolicyEngine) TestPolicy(policy *models.TestPolicy) (models.TestPolicyResult, error) {
	testResults := models.TestPolicyResult{}

	testResources, err := makeTestResources(policy)
	if err != nil {
		return testResults, err
	}
	engineInput := enginemodels.PolicyEngineInput{
		Policies: []enginemodels.Policy{
			{
				Body:          string(policy.Body),
				ID:            testPolicyID, // doesn't matter, we're only running one policy
				ResourceTypes: policy.ResourceTypes,
			},
		},
		Resources: testResources,
	}

	var engineOutput enginemodels.PolicyEngineOutput
	err = genericapi.Invoke(e.lambdaClient, e.lambdaName, &engineInput, &engineOutput)
	if err != nil {
		return testResults, errors.Wrap(err, "error invoking policy engine")
	}

	// Translate policy engine output to test results.
	return makeTestSummary(policy, engineOutput)
}

func makeTestSummary(policy *models.TestPolicy, engineOutput enginemodels.PolicyEngineOutput) (models.TestPolicyResult, error) {
	var testResults models.TestPolicyResult
	for _, result := range engineOutput.Resources {
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

		case len(result.Failed) > 0 && bool(test.ExpectedResult), len(result.Passed) > 0 && !bool(test.ExpectedResult):
			// The test result was not expected, so this test failed
			testResults.TestsFailed = append(testResults.TestsFailed, string(test.Name))
			testResults.TestSummary = false

		case len(result.Failed) > 0 && !bool(test.ExpectedResult), len(result.Passed) > 0 && bool(test.ExpectedResult):
			// The test result was as expected
			testResults.TestsPassed = append(testResults.TestsPassed, string(test.Name))
			testResults.TestSummary = true

		default:
			// This test didn't run (result.{Errored, Passed, Failed} are all empty). This must not happen absent a bug.
			return testResults, errors.Errorf("unable to run test for ruleID %s", result.ID)
		}
	}
	return testResults, nil
}

func makeTestResources(policy *models.TestPolicy) ([]enginemodels.Resource, error) {
	resources := make([]enginemodels.Resource, len(policy.Tests))
	for i, test := range policy.Tests {
		// TODO: Can swagger unmarshall this already?
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(test.Resource), &attrs); err != nil {
			return resources, errors.Wrapf(err, "tests[%d].resource is not valid json", i)
		}

		resources[i] = enginemodels.Resource{
			Attributes: attrs,
			ID:         testResourceID + strconv.Itoa(i),
			Type:       policyTestType(policy),
		}
	}
	return resources, nil
}

// policyTestType returns the resource type to use as the input to the policy engine.
// The engine picks the policy to run based on the input resource type. To make the engine run the
// input policy, we just pass one of its resource types in the input resource.
// If the policy is applicable for all resource types, a placeholder value is returned. The engine will
// run it for any resource type input.
func policyTestType(input *models.TestPolicy) string {
	if len(input.ResourceTypes) > 0 {
		return input.ResourceTypes[0]
	}
	return "__ALL__"
}
