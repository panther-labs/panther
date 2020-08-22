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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
	"github.com/panther-labs/panther/pkg/box"
)

type mockOutputsClient struct {
	outputs.API
	mock.Mock
}

func (m *mockOutputsClient) Slack(alert *deliveryModels.Alert, config *outputModels.SlackConfig) *outputs.AlertDeliveryResponse {
	args := m.Called(alert, config)
	return args.Get(0).(*outputs.AlertDeliveryResponse)
}

type mockLambdaClient struct {
	lambdaiface.LambdaAPI
	mock.Mock
}

func (m *mockLambdaClient) Invoke(input *lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*lambda.InvokeOutput), args.Error(1)
}

func sampleAlert() *deliveryModels.Alert {
	return &deliveryModels.Alert{
		AlertID:      aws.String("alert-id"),
		OutputIds:    []string{"output-id"},
		Severity:     "INFO",
		AnalysisID:   "test-rule-id",
		AnalysisName: box.String("test_rule_name"),
		CreatedAt:    time.Now().UTC(),
	}
}

var alertOutput = &outputModels.AlertOutput{
	OutputID:    aws.String("output-id"),
	OutputType:  aws.String("slack"),
	DisplayName: aws.String("slack:alerts"),
	OutputConfig: &outputModels.OutputConfig{
		Slack: &outputModels.SlackConfig{WebhookURL: "https://slack.com"},
	},
	DefaultForSeverity: []*string{aws.String("INFO")},
}

func setCaches() {
	cache.set(&outputsCache{
		Outputs:   []*outputModels.AlertOutput{alertOutput},
		Timestamp: time.Now(),
	})
}

func TestSendPanic(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	expectedResponse := DispatchStatus{
		AlertID:    *alert.AlertID,
		OutputID:   *alertOutput.OutputID,
		StatusCode: 500,
		Success:    false,
		Message:    "panic sending alert",
		NeedsRetry: false,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		panic("panicking")
	})
	go sendAlert(alert, alertOutput, ch)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendUnsupportedOutput(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	unsupportedOutput := &outputModels.AlertOutput{
		OutputType:  aws.String("unsupported"),
		DisplayName: aws.String("unsupported:destination"),
		OutputConfig: &outputModels.OutputConfig{
			Slack: &outputModels.SlackConfig{WebhookURL: "https://slack.com"},
		},
		OutputID: aws.String("output-id"),
	}
	expectedResponse := DispatchStatus{
		AlertID:    *alert.AlertID,
		OutputID:   *alertOutput.OutputID,
		StatusCode: 500,
		Success:    false,
		Message:    "unsupported output type",
		NeedsRetry: false,
	}
	go sendAlert(alert, unsupportedOutput, ch)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendResponseNil(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	// Create a nil response
	var response *outputs.AlertDeliveryResponse
	expectedResponse := DispatchStatus{
		AlertID:    *alert.AlertID,
		OutputID:   *alertOutput.OutputID,
		StatusCode: 500,
		Success:    false,
		Message:    "output response is nil",
		NeedsRetry: false,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	sendAlert(alert, alertOutput, ch)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendPermanentFailure(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	response := &outputs.AlertDeliveryResponse{
		StatusCode: 500,
		Success:    false,
		Message:    "permanent failure",
		Permanent:  true,
	}
	expectedResponse := DispatchStatus{
		AlertID:    *alert.AlertID,
		OutputID:   *alertOutput.OutputID,
		StatusCode: 500,
		Success:    false,
		Message:    "permanent failure",
		NeedsRetry: false,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	go sendAlert(alert, alertOutput, ch)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendTransientFailure(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	response := &outputs.AlertDeliveryResponse{
		StatusCode: 429,
		Success:    false,
		Message:    "transient failure",
		Permanent:  false,
	}
	expectedResponse := DispatchStatus{
		AlertID:    *alert.AlertID,
		OutputID:   *alertOutput.OutputID,
		StatusCode: 429,
		Success:    false,
		Message:    "transient failure",
		NeedsRetry: true,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	go sendAlert(alert, alertOutput, ch)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendSuccess(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	response := &outputs.AlertDeliveryResponse{
		StatusCode: 200,
		Success:    true,
		Message:    "successful response payload",
		Permanent:  false,
	}
	expectedResponse := DispatchStatus{
		AlertID:    *alert.AlertID,
		OutputID:   *alertOutput.OutputID,
		StatusCode: 200,
		Success:    true,
		Message:    "successful response payload",
		NeedsRetry: false,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	go sendAlert(alert, alertOutput, ch)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}

// func TestDispatchSuccess(t *testing.T) {
// 	mockClient := &mockOutputsClient{}
// 	outputClient = mockClient
// 	setCaches()
// 	mockClient.On("Slack", mock.Anything, mock.Anything).Return((*outputs.AlertDeliveryResponse)(nil))
// 	assert.True(t, dispatch(sampleAlert()))
// }

// func TestDispatchUseCachedDefault(t *testing.T) {
// 	mockLambdaClient := &mockLambdaClient{}
// 	lambdaClient = mockLambdaClient
// 	setCaches()
// 	alert := sampleAlert()
// 	alert.OutputIds = nil // Setting OutputIds in the alert to nil, in order to fetch default outputs
// 	assert.True(t, dispatch(alert))
// 	mockLambdaClient.AssertExpectations(t)
// }

// func TestDispatchUseNonCachedDefault(t *testing.T) {
// 	mockLambdaClient := &mockLambdaClient{}
// 	lambdaClient = mockLambdaClient

// 	outputs := &outputModels.GetOutputsOutput{alertOutput}
// 	payload, err := jsoniter.Marshal(outputs)
// 	require.NoError(t, err)

// 	mockLambdaResponse := &lambda.InvokeOutput{
// 		Payload: payload,
// 	}

// 	// Ensure the cache  is expired so we perform the lambda invocation
// 	cache.setExpiry(time.Now().Add(time.Second * time.Duration(-5*60)))
// 	mockLambdaClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil)
// 	alert := sampleAlert()
// 	alert.OutputIds = nil // Setting OutputIds in the alert to nil, in order to fetch default outputs
// 	assert.True(t, dispatch(alert))
// 	mockLambdaClient.AssertExpectations(t)
// }

// func TestAllGoRoutinesShouldComplete(t *testing.T) {
// 	mockLambdaClient := &mockLambdaClient{}
// 	lambdaClient = mockLambdaClient

// 	outputs := &outputModels.GetOutputsOutput{alertOutput}
// 	payload, err := jsoniter.Marshal(outputs)
// 	require.NoError(t, err)
// 	mockGetOutputsResponse := &lambda.InvokeOutput{
// 		Payload: payload,
// 	}

// 	// Ensure the cache  is expired so we perform the lambda invocation
// 	cache.setExpiry(time.Now().Add(time.Second * time.Duration(-5*60)))
// 	// setCaches()
// 	// Invoke once to get all outpts
// 	mockLambdaClient.On("Invoke", mock.Anything).Return(mockGetOutputsResponse, nil).Once()
// 	alert := sampleAlert()
// 	alert.OutputIds = nil // Setting OutputIds in the alert to nil, in order to fetch default outputs
// 	assert.True(t, dispatch(alert))
// 	mockLambdaClient.AssertExpectations(t)
// }
