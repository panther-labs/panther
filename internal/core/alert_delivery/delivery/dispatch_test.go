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
	"github.com/panther-labs/panther/pkg/genericapi"
)

func sampleAlert() *alertmodels.Alert {
	return &alertmodels.Alert{
		OutputIDs:  aws.StringSlice([]string{"output-id"}),
		Severity:   aws.String("INFO"),
		PolicyID:   aws.String("test-rule-id"),
		PolicyName: aws.String("test_rule_name"),
	}
}

func setCaches() {
	key := outputCacheKey{OutputID: "output-id"}
	alertOutputCache = map[outputCacheKey]cachedOutput{
		key: {
			Output: &outputmodels.AlertOutput{
				OutputType:  aws.String("slack"),
				DisplayName: aws.String("slack:alerts"),
				OutputConfig: &outputmodels.OutputConfig{
					Slack: &outputmodels.SlackConfig{WebhookURL: aws.String("https://slack.com")},
				},
				VerificationStatus: aws.String(outputmodels.VerificationStatusSuccess),
			},
			Timestamp: time.Now(),
		},
	}

	defaultOutputIDsCache = &cachedOutputIDs{
		Outputs: map[string][]*string{
			"INFO": aws.StringSlice([]string{"default-output-id"}),
		},
		Timestamp: time.Now(),
	}
}

func TestFailureToRetrieveOutput(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient

	ch := make(chan outputStatus, 1)
	alertOutputCache = make(map[outputCacheKey]cachedOutput)

	send(sampleAlert(), "output-id", ch)
	assert.Equal(t, outputStatus{outputID: "output-id", needsRetry: true}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendPanic(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient

	ch := make(chan outputStatus, 1)
	mockLambdaClient.On("Invoke", mock.Anything).Run(func(args mock.Arguments) {
		panic("panicking")
	})
	go send(sampleAlert(), "output-id", ch)
	assert.Equal(t, outputStatus{outputID: "output-id"}, <-ch)
	mockLambdaClient.AssertExpectations(t)
}

func TestSendUnsupportedOutput(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	ch := make(chan outputStatus, 1)
	key := outputCacheKey{
		OutputID: "output-id",
	}
	alertOutputCache[key].Output.OutputConfig.Slack = nil

	send(sampleAlert(), "output-id", ch)
	assert.Equal(t, outputStatus{outputID: "output-id"}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendNotVerifiedOutput(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	ch := make(chan outputStatus, 1)
	key := outputCacheKey{
		OutputID: "output-id",
	}
	alertOutputCache[key].Output.VerificationStatus = aws.String(outputmodels.VerificationStatusPending)

	send(sampleAlert(), "output-id", ch)
	assert.Equal(t, outputStatus{outputID: "output-id", success: false, needsRetry: false}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendTransientFailure(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	ch := make(chan outputStatus, 1)
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(&outputs.AlertDeliveryError{})

	send(sampleAlert(), "output-id", ch)
	assert.Equal(t, outputStatus{outputID: "output-id", needsRetry: true}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendOutputDoesNotExist(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient
	ch := make(chan outputStatus, 1)

	lambdaErr, err := jsoniter.Marshal(genericapi.LambdaError{ErrorType: aws.String("DoesNotExistError")})
	require.NoError(t, err)
	lambdaOutput := &lambda.InvokeOutput{
		FunctionError: aws.String("error"),
		Payload:       lambdaErr,
	}

	mockLambdaClient.On("Invoke", mock.Anything).Return(lambdaOutput, nil)

	send(sampleAlert(), "non-existent-output", ch)
	assert.Equal(t, outputStatus{outputID: "non-existent-output", needsRetry: false}, <-ch)
	mockLambdaClient.AssertExpectations(t)
}

func TestSendSuccess(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	mockClient.On("Slack", mock.Anything, mock.Anything).Return((*outputs.AlertDeliveryError)(nil))
	ch := make(chan outputStatus, 1)

	send(sampleAlert(), "output-id", ch)
	assert.Equal(t, outputStatus{outputID: "output-id", success: true}, <-ch)
	mockClient.AssertExpectations(t)
}

func TestDispatchFailure(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	setCaches()
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(&outputs.AlertDeliveryError{})

	alert := sampleAlert()
	assert.False(t, dispatch(alert))
	assert.Equal(t, aws.StringSlice([]string{"output-id"}), alert.OutputIDs)
	mockClient.AssertExpectations(t)
}

func TestDispatchSuccess(t *testing.T) {
	outputClient = &mockOutputsClient{}
	setCaches()
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

	mockLambdaResponse := &lambda.InvokeOutput{
		Payload: []byte(`{"defaults": [{"severity": "INFO", "outputIds": ["output-id"]}]}`),
	}

	mockLambdaClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil)
	alert := sampleAlert()
	alert.OutputIDs = nil       //Setting OutputIds in the alert to nil, in order to fetch default outputs
	defaultOutputIDsCache = nil // Clearing the default output ids cache

	assert.True(t, dispatch(alert))
	mockLambdaClient.AssertExpectations(t)
}

func TestAllGoRoutinesShouldComplete(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient

	mockLambdaResponse := &lambda.InvokeOutput{
		Payload: []byte(`{"defaults": [{"severity": "INFO", "outputIds": ["output-id-1", "output-id-2"]}]}`),
	}

	mockLambdaClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Twice().Run(func(args mock.Arguments) {
		time.Sleep(time.Second)
	})
	alert := sampleAlert()
	alert.OutputIDs = nil       //Setting OutputIds in the alert to nil, in order to fetch default outputs
	defaultOutputIDsCache = nil // Clearing the default output ids cache

	assert.True(t, dispatch(alert))
	mockLambdaClient.AssertExpectations(t)
}

func TestDispatchUseDefaultIsEmpty(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient

	mockLambdaResponse := &lambda.InvokeOutput{
		Payload: []byte(`{"defaults": [{"severity": "INFO"}]}`),
	}

	mockLambdaClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil)

	setCaches()
	alert := sampleAlert()
	alert.OutputIDs = nil //Setting OutputIds in the alert to nil, in order to fetch default outputs
	alert.Severity = aws.String("INFO")
	defaultOutputIDsCache = nil

	assert.True(t, dispatch(alert))
	mockLambdaClient.AssertExpectations(t)
}

func TestDispatchFailIfFailureToGetDefaults(t *testing.T) {
	mockLambdaClient := &mockLambdaClient{}
	lambdaClient = mockLambdaClient

	mockLambdaClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error"))

	setCaches()
	alert := sampleAlert()
	alert.OutputIDs = nil       //Setting OutputIds in the alert to nil, in order to fetch default outputs
	defaultOutputIDsCache = nil // Clearing the default output ids cache

	assert.False(t, dispatch(alert))
	mockLambdaClient.AssertExpectations(t)
}
