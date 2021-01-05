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

	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestGetAlertOutputsFromDefaultSeverity(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient
	output := &outputModels.GetOutputsOutput{
		{
			OutputID:           aws.String("default-info-1"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("default-info-2"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("default-medium"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		},
	}
	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()
	alert := sampleAlert()
	alert.OutputIds = nil

	expectedResult := []*outputModels.AlertOutput{{
		OutputID:           aws.String("default-info-1"),
		DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
	}, {
		OutputID:           aws.String("default-info-2"),
		DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
	}}

	result, err := getAlertOutputs(alert)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	result, err = getAlertOutputs(alert)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockClient.AssertExpectations(t)
}

func TestGetAlertOutputsFromOutputIds(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	output := &outputModels.GetOutputsOutput{
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("output-id-2"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("output-id-3"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		},
	}
	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()
	alert := sampleAlert()
	alert.OutputIds = []string{"output-id", "output-id-3", "output-id-not"}

	expectedResult := []*outputModels.AlertOutput{{
		OutputID:           aws.String("output-id"),
		DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
	}, {
		OutputID:           aws.String("output-id-3"),
		DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
	}}

	result, err := getAlertOutputs(alert)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	mockClient.AssertExpectations(t)
}

func TestGetAlertOutputsIdsError(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient
	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error"))

	alert := sampleAlert()
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

func TestGetUniqueAlertOutputs(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	output := &outputModels.GetOutputsOutput{
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("output-id-2"),
			DefaultForSeverity: aws.StringSlice([]string{"LOW"}),
		},
		{
			OutputID:           aws.String("output-id-3"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		},
	}
	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()
	alert := sampleAlert()
	alert.OutputIds = []string{"output-id", "output-id", "output-id"}

	expectedResult := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
	}

	result, err := getAlertOutputs(alert)
	uniqueResult := getUniqueOutputs(result)
	require.NoError(t, err)
	assert.Equal(t, expectedResult, uniqueResult)

	mockClient.AssertExpectations(t)
}

func TestUniqueAlertOutputs(t *testing.T) {
	// Construct a list of outputs to test for uniqueness
	// We put items out of order on purpose to test for sorting
	alertOutputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id-2"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"LOW"}),
		},
		{
			OutputID:           aws.String("output-id-2"),
			DefaultForSeverity: aws.StringSlice([]string{"LOW"}),
		},
		{
			OutputID:           aws.String("output-id-2"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		},
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		},
	}

	// The expected results should be the last seen entry for a given outputID
	expectedAlertOutputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		},
		{
			OutputID:           aws.String("output-id-2"),
			DefaultForSeverity: aws.StringSlice([]string{"MEDIUM"}),
		},
	}

	uniqueResult := getUniqueOutputs(alertOutputs)
	assert.Equal(t, expectedAlertOutputs, uniqueResult)
}
