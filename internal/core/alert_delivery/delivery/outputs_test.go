package delivery

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

func TestGetOutput(t *testing.T) {
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient
	lambdaResponse := &lambda.InvokeOutput{
		Payload: []byte(`{"displayName": "alert-channel", "outputConfig" : {"slack": {"webhookURL": "slack.com"}}}`),
	}

	mockClient.On("Invoke", mock.Anything).Return(lambdaResponse, nil)
	result, err := getOutput("test-output-id")

	require.Nil(t, err)
	assert.Equal(t, aws.String("alert-channel"), result.DisplayName)
	assert.NotNil(t, result.OutputConfig.Slack)

	// Now the result should be cached
	cachedResult, err := getOutput("test-output-id")

	require.NoError(t, err)
	assert.Equal(t, result, cachedResult)
	mockClient.AssertExpectations(t)
}

func TestGetOutputError(t *testing.T) {
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient
	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error"))

	result, err := getOutput("other")
	require.Error(t, err)
	assert.Nil(t, result)
	mockClient.AssertExpectations(t)
}

func TestGetAlertOutputIds(t *testing.T) {
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient

	output := &outputmodels.GetDefaultOutputsOutput{
		Defaults: []*outputmodels.DefaultOutputs{
			{
				Severity:  aws.String("INFO"),
				OutputIDs: aws.StringSlice([]string{"default-info-1", "default-info-2"}),
			},
			{
				Severity:  aws.String("MEDIUM"),
				OutputIDs: aws.StringSlice([]string{"default-medium"}),
			},
		},
	}
	payload, err := jsoniter.Marshal(output)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}

	defaultOutputIDsCache = nil // Clear the cache
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil)
	alert := sampleAlert()
	alert.OutputIDs = nil

	result, err := getAlertOutputIds(alert)

	require.NoError(t, err)
	assert.Equal(t, aws.StringSlice([]string{"default-info-1", "default-info-2"}), result)

	// Now the result should be cached
	require.NotNil(t, defaultOutputIDsCache)
	assert.Equal(t, map[string][]*string{
		"INFO":   aws.StringSlice([]string{"default-info-1", "default-info-2"}),
		"MEDIUM": aws.StringSlice([]string{"default-medium"}),
	}, defaultOutputIDsCache.Outputs)

	cachedResult, err := getAlertOutputIds(alert)

	require.NoError(t, err)
	assert.Equal(t, result, cachedResult)
	mockClient.AssertExpectations(t)
}

func TestGetAlertOutputsIdsError(t *testing.T) {
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient
	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error"))

	result, err := getOutput("other")
	require.Error(t, err)
	assert.Nil(t, result)
	mockClient.AssertExpectations(t)
}
