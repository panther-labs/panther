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

	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
)

func genAlertOutput() *outputModels.AlertOutput {
	return &outputModels.AlertOutput{
		OutputID:    aws.String("output-id"),
		OutputType:  aws.String("slack"),
		DisplayName: aws.String("slack:alerts"),
		OutputConfig: &outputModels.OutputConfig{
			Slack: &outputModels.SlackConfig{WebhookURL: "https://slack.com"},
		},
		DefaultForSeverity: []*string{aws.String("INFO")},
	}
}

func TestSendPanic(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	alertOutput := genAlertOutput()
	dispatchedAt := time.Now().UTC()

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

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	alertOutput := genAlertOutput()
	dispatchedAt := time.Now().UTC()

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

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	alertOutput := genAlertOutput()
	dispatchedAt := time.Now().UTC()

	// Create a nil response
	response := (*outputs.AlertDeliveryResponse)(nil)
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

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	alertOutput := genAlertOutput()
	dispatchedAt := time.Now().UTC()

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

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	alertOutput := genAlertOutput()
	dispatchedAt := time.Now().UTC()

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

	ch := make(chan DispatchStatus, 1)
	alert := sampleAlert()
	alertOutput := genAlertOutput()
	dispatchedAt := time.Now().UTC()

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
