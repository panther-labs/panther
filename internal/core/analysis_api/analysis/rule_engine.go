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

func (e *RuleEngine) TestRule(rule *models.TestPolicy) (models.TestPolicyResult, error) {
	empty := models.TestPolicyResult{}

	// Build the list of events to run the rule against
	inputEvents := make([]enginemodels.Event, len(rule.Tests))
	for i, test := range rule.Tests {
		// TODO(giorgosp): Can swagger unmarshall this already?
		var attrs map[string]interface{}
		if err := jsoniter.UnmarshalFromString(string(test.Resource), &attrs); err != nil {
			return empty, errors.Wrapf(err, "tests[%d].event is not valid json", i)
		}

		inputEvents[i] = enginemodels.Event{
			Data: attrs,
			ID:   testResourceID + strconv.Itoa(i),
		}
	}

	input := enginemodels.RulesEngineInput{
		Rules: []enginemodels.Rule{
			{
				Body:     string(rule.Body),
				ID:       testPolicyID, // doesn't matter as we're only running one rule
				LogTypes: rule.ResourceTypes,
			},
		},
		Events: inputEvents,
	}

	// Send the request to the rule-engine
	var engineOutput enginemodels.RulesEngineOutput
	err := genericapi.Invoke(e.lambdaClient, e.lambdaName, &input, &engineOutput)
	if err != nil {
		return empty, errors.Wrap(err, "error invoking rule engine")
	}

	// Translate rule engine output to test results.
	testResults, err := makeTestSummaryRule(rule, engineOutput)
	return testResults, err
}

func makeTestSummaryRule(rule *models.TestPolicy, engineOutput enginemodels.RulesEngineOutput) (models.TestPolicyResult, error) {
	// Normalize rule engine output to policy engine output to facilitate consistent handling
	// in makeTestSummary().
	output := enginemodels.PolicyEngineOutput{
		Resources: make([]enginemodels.Result, len(engineOutput.Events)),
	}
	for i, event := range engineOutput.Events {
		output.Resources[i] = event.ToResult()
	}
	return makeTestSummary(rule, output)
}
