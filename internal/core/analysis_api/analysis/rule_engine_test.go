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
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/analysis"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

type mockLambdaClient struct {
	mock.Mock
	lambdaiface.LambdaAPI
}

func (m *mockLambdaClient) Invoke(i *lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	retargs := m.Called(i)
	return retargs.Get(0).(*lambda.InvokeOutput), retargs.Error(1)
}

var lambdaClient = mockLambdaClient{}

func TestRuleEngine_TestRule(t *testing.T) {
	output := lambda.InvokeOutput{
		Payload: mustMarshal(analysis.RulesEngineOutput{
			Results: []analysis.RuleResult{
				{
					ID:                 "0",
					RuleID:             testRuleID,
					RuleOutput:         true,
					Errored:            false,
					TitleOutput:        "alert-title",
					DedupOutput:        "alert-dedup",
					AlertContextOutput: `{"key":"value"}`,
				},
			},
		}),
		StatusCode: aws.Int64(200),
	}

	lambdaClient.On("Invoke", mock.Anything).Return(&output, nil)

	ruleEngine := RuleEngine{
		lambdaClient: &lambdaClient,
	}

	testRuleInput := &models.TestRuleInput{
		Body: `
def rule(e): 
	return True

def title(e):
	return 'alert-title'

def dedup(e):
	return 'alert-dedup'
`,
		LogTypes: []string{"Resource.Type"},
		Tests: []models.UnitTest{
			{
				Name:           "This will be True",
				ExpectedResult: true,
				Resource:       `{}`,
			},
		},
	}
	res, err := ruleEngine.TestRule(testRuleInput)

	require.NoError(t, err)
	lambdaClient.AssertExpectations(t)

	expected := &models.TestRuleOutput{
		Results: []models.TestRuleRecord{
			{
				ID:     "0",
				Name:   "This will be True",
				Passed: true,
				Functions: models.TestRuleRecordFunctions{
					Rule: &models.TestDetectionSubRecord{
						Output: aws.String("true"),
					},
					Title: &models.TestDetectionSubRecord{
						Output: aws.String("alert-title"),
					},
					Dedup: &models.TestDetectionSubRecord{
						Output: aws.String("alert-dedup"),
					},
					AlertContext: &models.TestDetectionSubRecord{
						Output: aws.String(`{"key":"value"}`),
					},
				},
			},
		},
	}
	require.EqualValues(t, expected, res)
}

func mustMarshal(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
