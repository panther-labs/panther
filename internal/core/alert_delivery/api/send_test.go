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

var (
	alertOutput = &outputModels.AlertOutput{
		OutputID:    aws.String("output-id"),
		OutputType:  aws.String("slack"),
		DisplayName: aws.String("slack:alerts"),
		OutputConfig: &outputModels.OutputConfig{
			Slack: &outputModels.SlackConfig{WebhookURL: "https://slack.com"},
		},
		DefaultForSeverity: []*string{aws.String("INFO")},
	}
	dispatchedAt = time.Now().UTC()
)

func setCaches() {
	outputsCache.set(&alertOutputsCache{
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
		Alert:        *alert,
		OutputID:     *alertOutput.OutputID,
		StatusCode:   500,
		Success:      false,
		Message:      "panic sending alert",
		NeedsRetry:   false,
		DispatchedAt: dispatchedAt,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		panic("panicking")
	})
	go sendAlert(alert, alertOutput, dispatchedAt, ch)
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
		Alert:        *alert,
		OutputID:     *alertOutput.OutputID,
		StatusCode:   500,
		Success:      false,
		Message:      "unsupported output type",
		NeedsRetry:   false,
		DispatchedAt: dispatchedAt,
	}
	go sendAlert(alert, unsupportedOutput, dispatchedAt, ch)
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
		Alert:        *alert,
		OutputID:     *alertOutput.OutputID,
		StatusCode:   500,
		Success:      false,
		Message:      "output response is nil",
		NeedsRetry:   false,
		DispatchedAt: dispatchedAt,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	sendAlert(alert, alertOutput, dispatchedAt, ch)
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
		Alert:        *alert,
		OutputID:     *alertOutput.OutputID,
		StatusCode:   500,
		Success:      false,
		Message:      "permanent failure",
		NeedsRetry:   false,
		DispatchedAt: dispatchedAt,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	go sendAlert(alert, alertOutput, dispatchedAt, ch)
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
		Alert:        *alert,
		OutputID:     *alertOutput.OutputID,
		StatusCode:   429,
		Success:      false,
		Message:      "transient failure",
		NeedsRetry:   true,
		DispatchedAt: dispatchedAt,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	go sendAlert(alert, alertOutput, dispatchedAt, ch)
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
		Alert:        *alert,
		OutputID:     *alertOutput.OutputID,
		StatusCode:   200,
		Success:      true,
		Message:      "successful response payload",
		NeedsRetry:   false,
		DispatchedAt: dispatchedAt,
	}
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(response)
	go sendAlert(alert, alertOutput, dispatchedAt, ch)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}
