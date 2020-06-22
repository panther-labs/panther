package delivery

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
	"github.com/panther-labs/panther/pkg/box"
)

func sampleAlert() *alertmodels.Alert {
	return &alertmodels.Alert{
		OutputIDs:    []string{"output-id"},
		Severity:     "INFO",
		AnalysisID:   "test-rule-id",
		AnalysisName: box.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}
}

var alertOutput = &outputmodels.AlertOutput{
	OutputType:  aws.String("slack"),
	DisplayName: aws.String("slack:alerts"),
	OutputConfig: &outputmodels.OutputConfig{
		Slack: &outputmodels.SlackConfig{WebhookURL: "https://slack.com"},
	},
	OutputID: aws.String("output-id"),
}

func setCaches() {
	cache = &outputsCache{
		Outputs:   []*outputmodels.AlertOutput{alertOutput},
		Timestamp: time.Now(),
	}
}

func TestSendPanic(t *testing.T) {
	mockOutputsClient := &mockOutputsClient{}
	outputClient = mockOutputsClient

	ch := make(chan outputStatus, 1)
	mockOutputsClient.On("Slack", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		panic("panicking")
	})
	go send(sampleAlert(), alertOutput, ch)
	require.Equal(t, outputStatus{outputID: *alertOutput.OutputID}, <-ch)
	mockOutputsClient.AssertExpectations(t)
}

func TestSendUnsupportedOutput(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	ch := make(chan outputStatus, 1)

	send(sampleAlert(), alertOutput, ch)
	assert.Equal(t, outputStatus{outputID: *alertOutput.OutputID}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendTransientFailure(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	ch := make(chan outputStatus, 1)
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(&outputs.AlertDeliveryError{})

	send(sampleAlert(), alertOutput, ch)
	assert.Equal(t, outputStatus{outputID: *alertOutput.OutputID, needsRetry: true}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendSuccess(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	mockClient.On("Slack", mock.Anything, mock.Anything).Return((*outputs.AlertDeliveryError)(nil))
	ch := make(chan outputStatus, 1)

	send(sampleAlert(), alertOutput, ch)
	assert.Equal(t, outputStatus{outputID: *alertOutput.OutputID, success: true}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestDispatchFailure(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(&outputs.AlertDeliveryError{})

	assert.False(t, dispatch(sampleAlert()))
	mockClient.AssertExpectations(t)
}

func TestDispatchSuccess(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	mockClient.On("Slack", mock.Anything, mock.Anything).Return((*outputs.AlertDeliveryError)(nil))
	assert.True(t, dispatch(sampleAlert()))
}

func TestDispatchUseCachedDefault(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient

	setCaches()
	alert := sampleAlert()
	alert.OutputIDs = nil //Setting OutputIds in the alert to nil, in order to fetch default outputs

	assert.True(t, dispatch(alert))
	mockLambdaClient.AssertExpectations(t)
}

func TestDispatchUseNonCachedDefault(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient

	outputs := &outputmodels.GetOutputsOutput{
		{
			OutputID:           aws.String("output-id"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
	}
	payload, err := jsoniter.Marshal(outputs)
	require.NoError(t, err)

	mockLambdaResponse := &lambda.InvokeOutput{
		Payload: payload,
	}

	mockLambdaClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil)
	alert := sampleAlert()
	alert.OutputIDs = nil //Setting OutputIds in the alert to nil, in order to fetch default outputs
	cache = nil           // Setting cache to nil, so we fetch latest outputs IDs from Lambda
	assert.True(t, dispatch(alert))
	mockLambdaClient.AssertExpectations(t)
}

func TestAllGoRoutinesShouldComplete(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient

	outputs := &outputmodels.GetOutputsOutput{
		{
			OutputID:           aws.String("output-id-1"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
		{
			OutputID:           aws.String("output-id-2"),
			DefaultForSeverity: aws.StringSlice([]string{"INFO"}),
		},
	}
	payload, err := jsoniter.Marshal(outputs)
	require.NoError(t, err)
	mockGetOutputsResponse := &lambda.InvokeOutput{
		Payload: payload,
	}

	// Invoke once to get all outpts
	mockLambdaClient.On("Invoke", mock.Anything).Return(mockGetOutputsResponse, nil).Once()
	alert := sampleAlert()
	alert.OutputIDs = nil //Setting OutputIds in the alert to nil, in order to fetch default outputs
	cache = nil           // Clearing the default output ids cache

	assert.True(t, dispatch(alert))
	mockLambdaClient.AssertExpectations(t)
}
