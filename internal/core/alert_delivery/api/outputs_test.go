package api

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

var output = &outputModels.GetOutputsOutput{
	{
		OutputID:           aws.String("output-id-1"),
		DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
	},
	{
		OutputID:           aws.String("output-id-2"),
		DefaultForSeverity: aws.StringSlice([]string{"LOW"}),
		AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
	},
	{
		OutputID:           aws.String("output-id-3"),
		DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
	},
	{
		OutputID:           aws.String("output-id-4"),
		DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
		AlertTypes:         []string{deliverymodel.PolicyType},
	},
	{
		OutputID:           aws.String("output-id-5"),
		DefaultForSeverity: aws.StringSlice([]string{"CRITICAL"}),
		AlertTypes:         []string{deliverymodel.PolicyType},
	},
}

func TestGetAlertOutputsFromDynamicDestinations(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// The combination of 'INFO' and 'RuleType' and dynamic overrides should yield one result
	alert := &deliverymodel.Alert{
		AlertID:      aws.String("alert-id"),
		Type:         deliverymodel.RuleType,
		Destinations: []string{"output-id-1", "output-id-3", "output-id-not"},              // Dynamic overrides
		OutputIds:    []string{"output-id-1", "output-id-2", "output-id-3", "output-id-4"}, // Destination overrides
		Severity:     "INFO",
		AnalysisID:   "test-rule-id",
		AnalysisName: aws.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}
	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-1"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
		{
			OutputID:           aws.String("output-id-3"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
	}

	result, err := getAlertOutputs(alert)
	uniqueResult := getUniqueOutputs(result)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, uniqueResult)

	mockClient.AssertExpectations(t)
}
func TestGetAlertOutputsFromDestinationOverrides(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// The combination of 'INFO' and 'RuleType' and destination overrides should yield one result
	alert := &deliverymodel.Alert{
		AlertID:      aws.String("alert-id"),
		Type:         deliverymodel.RuleType,
		Destinations: nil,                                                     // Dynamic overrides
		OutputIds:    []string{"output-id-1", "output-id-3", "output-id-not"}, // Destination overrides
		Severity:     "INFO",
		AnalysisID:   "test-rule-id",
		AnalysisName: aws.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}
	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-1"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
		{
			OutputID:           aws.String("output-id-3"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
	}

	result, err := getAlertOutputs(alert)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	mockClient.AssertExpectations(t)
}

func TestGetAlertOutputsFromDefaultSeverity(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient
	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// The combination of 'INFO' and 'RuleType' should yield one result
	alert := &deliverymodel.Alert{
		AlertID:      aws.String("alert-id"),
		Type:         deliverymodel.RuleType,
		Destinations: nil, // Dynamic overrides
		OutputIds:    nil, // Destination overrides
		Severity:     "INFO",
		AnalysisID:   "test-rule-id",
		AnalysisName: aws.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}
	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-1"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
			AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
		},
	}

	result, err := getAlertOutputs(alert)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	result, err = getAlertOutputs(alert)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockClient.AssertExpectations(t)
}

func TestGetAlertOutputsFromAlertType(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient
	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// The combination of 'HIGH' and 'PolicyType' should yield one result
	alert := &deliverymodel.Alert{
		AlertID:      aws.String("alert-id"),
		Type:         deliverymodel.PolicyType,
		Destinations: nil, // Dynamic overrides
		OutputIds:    nil, // Destination overrides
		Severity:     "HIGH",
		AnalysisID:   "test-rule-id",
		AnalysisName: aws.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}

	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-4"),
			DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
			AlertTypes:         []string{deliverymodel.PolicyType},
		},
	}

	result, err := getAlertOutputs(alert)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	result, err = getAlertOutputs(alert)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockClient.AssertExpectations(t)
}

func TestGetAlertOutputsIdsError(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient
	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error"))

	alert := &deliverymodel.Alert{
		AlertID:      aws.String("alert-id"),
		Type:         deliverymodel.RuleType,
		OutputIds:    nil,
		Severity:     "INFO",
		AnalysisID:   "test-rule-id",
		AnalysisName: aws.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}
	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	result, err := getAlertOutputs(alert)
	require.Error(t, err)
	assert.Nil(t, result)
	mockClient.AssertExpectations(t)
}

func TestUniqueAlertOutputs(t *testing.T) {
	// Construct a list of outputs to test for uniqueness
	// We put items out of order on purpose to test for sorting
	alertOutputs := []*outputModels.AlertOutput{
		{
			OutputID: aws.String("output-id-2"),
		},
		{
			OutputID: aws.String("output-id"),
		},
		{
			OutputID: aws.String("output-id"),
		},
		{
			OutputID: aws.String("output-id-2"),
		},
		{
			OutputID: aws.String("output-id-2"),
		},
		{
			OutputID: aws.String("output-id"),
		},
	}

	// The expected results should be the last seen entry for a given outputID
	expectedAlertOutputs := []*outputModels.AlertOutput{
		{
			OutputID: aws.String("output-id"),
		},
		{
			OutputID: aws.String("output-id-2"),
		},
	}

	uniqueResult := getUniqueOutputs(alertOutputs)
	assert.Equal(t, expectedAlertOutputs, uniqueResult)
}
