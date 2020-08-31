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
)

func TestGetAlertOutputsFromDefaultSeverity(t *testing.T) {
	mockClient := &mockLambdaClient{}
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

	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5))) // Trigger cache expiration
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
	mockClient := &mockLambdaClient{}
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

	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5))) // Trigger cache expiration
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
	mockClient := &mockLambdaClient{}
	lambdaClient = mockClient
	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error"))

	alert := sampleAlert()
	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5))) // Trigger cache expiration

	result, err := getAlertOutputs(alert)
	require.Error(t, err)
	assert.Nil(t, result)
	mockClient.AssertExpectations(t)
}
