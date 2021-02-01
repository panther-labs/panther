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
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
	"github.com/panther-labs/panther/pkg/testutils"
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
	ctx := context.Background()
	mockClient.On("Slack", ctx, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		panic("panicking")
	})
	go sendAlert(ctx, alert, alertOutput, dispatchedAt, ch, outputClient)
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
	ctx := context.Background()
	go sendAlert(ctx, alert, unsupportedOutput, dispatchedAt, ch, outputClient)
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
	ctx := context.Background()
	mockClient.On("Slack", ctx, mock.Anything, mock.Anything).Return(response)
	go sendAlert(ctx, alert, alertOutput, dispatchedAt, ch, outputClient)
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
	ctx := context.Background()
	mockClient.On("Slack", ctx, mock.Anything, mock.Anything).Return(response)
	go sendAlert(ctx, alert, alertOutput, dispatchedAt, ch, outputClient)
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
	ctx := context.Background()
	mockClient.On("Slack", ctx, mock.Anything, mock.Anything).Return(response)
	go sendAlert(ctx, alert, alertOutput, dispatchedAt, ch, outputClient)
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
	ctx := context.Background()
	mockClient.On("Slack", ctx, mock.Anything, mock.Anything).Return(response)
	go sendAlert(ctx, alert, alertOutput, dispatchedAt, ch, outputClient)
	assert.Equal(t, expectedResponse, <-ch)
	mockClient.AssertExpectations(t)
}

func TestSendAlertsTimeout(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient
	mockOutputClient := &mockOutputsClient{}
	outputClient = mockOutputClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: "A test alert",
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             "A runbook link",
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliverymodel.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	slackConfig := &outputModels.OutputConfig{
		Slack: &outputModels.SlackConfig{WebhookURL: "https://slack.com"},
	}
	alertOutputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String(outputIds[0]),
			OutputType:         aws.String("slack"),
			OutputConfig:       slackConfig,
			DefaultForSeverity: []*string{aws.String("INFO")},
		},
		{
			OutputID:           aws.String(outputIds[1]),
			OutputType:         aws.String("slack"),
			OutputConfig:       slackConfig,
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM")},
		},
		{
			OutputID:           aws.String(outputIds[2]),
			OutputType:         aws.String("slack"),
			OutputConfig:       slackConfig,
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
		},
	}

	// AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput
	alertOutputMap := AlertOutputMap{
		alert: alertOutputs,
	}

	expectedDispatchStatuses := []DispatchStatus{
		{
			Alert:      *alert,
			OutputID:   outputIds[0],
			Message:    "Timeout: the upstream service did not respond back in time",
			StatusCode: 504,
			Success:    false,
			NeedsRetry: true,
		},
		{
			Alert:      *alert,
			OutputID:   outputIds[1],
			Message:    "Timeout: the upstream service did not respond back in time",
			StatusCode: 504,
			Success:    false,
			NeedsRetry: true,
		},
		{
			Alert:      *alert,
			OutputID:   outputIds[2],
			Message:    "Timeout: the upstream service did not respond back in time",
			StatusCode: 504,
			Success:    false,
			NeedsRetry: true,
		},
	}

	slowResponse := &outputs.AlertDeliveryResponse{
		StatusCode: 200,
		Success:    true,
		Message:    "successful response payload",
		Permanent:  false,
	}

	// A normal aws lambda context will have a deadline, so we need
	// to simulate one with a deadline attached that has already expired
	ctx := context.Background()
	deadline := time.Now()
	expiredCtx, cancel := context.WithDeadline(ctx, deadline)
	// Defer cancelling until the end of the test as best practice.
	defer cancel()

	// Overwrite the global buffer for this test.
	// Remember, this buffer represents a soft deadline
	// so that the lambda has enough time to exit successfully.
	//
	// lambda invocation   soft deadline         hard deadline
	// |-------------------------|--------< buffer >---------|
	softDeadlineDuration = 30 * time.Second

	// set up our slow Slack mock
	mockOutputClient.On("Slack", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(15 * time.Second)
	}).Return(slowResponse).Maybe()

	// We get our results, but the DispachedAt timestamp is present
	// so we will ignore that for now
	dispatchStatusesResult := sendAlerts(expiredCtx, alertOutputMap, outputClient)

	mockOutputClient.AssertExpectations(t)

	modifiedDispatchStatusesResult := []DispatchStatus{}
	for _, dispatchStatus := range dispatchStatusesResult {
		newStatus := DispatchStatus{
			Alert:      dispatchStatus.Alert,
			OutputID:   dispatchStatus.OutputID,
			Message:    dispatchStatus.Message,
			StatusCode: dispatchStatus.StatusCode,
			Success:    dispatchStatus.Success,
			NeedsRetry: dispatchStatus.NeedsRetry,
			// This is calculated internally and is tough to
			// predict due to async threads. However, for the
			// sake of this test, we don't need to test
			// for timestamp equivalence. We only need to check
			// for the other fields.
			// DispatchedAt: dispatchStatus.DispatchedAt,
		}
		modifiedDispatchStatusesResult = append(modifiedDispatchStatusesResult, newStatus)
	}
	assert.Equal(t, len(expectedDispatchStatuses), len(modifiedDispatchStatusesResult))

	// since the result could be out of order, we need check for item equivalence and not the order
	equalDispatchCount := 0
	for _, expStatus := range expectedDispatchStatuses {
		for _, status := range modifiedDispatchStatusesResult {
			if expStatus.OutputID == status.OutputID {
				assert.Equal(t, expStatus, status)
				equalDispatchCount++
			}
		}
	}
	assert.Equal(t, 3, equalDispatchCount)
}

func TestSendAlertsSuccess(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient
	mockOutputClient := &mockOutputsClient{}
	outputClient = mockOutputClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: "A test alert",
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             "A runbook link",
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliverymodel.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}

	slackConfig := &outputModels.OutputConfig{
		Slack: &outputModels.SlackConfig{WebhookURL: "https://slack.com"},
	}
	alertOutputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String(outputIds[0]),
			OutputType:         aws.String("slack"),
			OutputConfig:       slackConfig,
			DefaultForSeverity: []*string{aws.String("INFO")},
		},
		{
			OutputID:           aws.String(outputIds[1]),
			OutputType:         aws.String("slack"),
			OutputConfig:       slackConfig,
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM")},
		},
		{
			OutputID:           aws.String(outputIds[2]),
			OutputType:         aws.String("slack"),
			OutputConfig:       slackConfig,
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
		},
	}

	// AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput
	alertOutputMap := AlertOutputMap{
		alert: alertOutputs,
	}

	expectedDispatchStatuses := []DispatchStatus{
		{
			Alert:      *alert,
			OutputID:   outputIds[0],
			Message:    "successful response payload",
			StatusCode: 200,
			Success:    true,
			NeedsRetry: false,
		},
		{
			Alert:      *alert,
			OutputID:   outputIds[1],
			Message:    "successful response payload",
			StatusCode: 200,
			Success:    true,
			NeedsRetry: false,
		},
		{
			Alert:      *alert,
			OutputID:   outputIds[2],
			Message:    "successful response payload",
			StatusCode: 200,
			Success:    true,
			NeedsRetry: false,
		},
	}

	slowResponse := &outputs.AlertDeliveryResponse{
		StatusCode: 200,
		Success:    true,
		Message:    "successful response payload",
		Permanent:  false,
	}

	// A normal aws lambda context will have a deadline, so we need
	// to simulate one with a deadline attached that WILL NOT expire
	// while running `mage test:go`
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Minute)
	expiredCtx, cancel := context.WithDeadline(ctx, deadline)
	// Defer cancelling until the end of the test as best practice.
	defer cancel()

	// Overwrite the global buffer for this test.
	// Remember, this buffer represents a soft deadline
	// so that the lambda has enough time to exit successfully.
	//
	// lambda invocation   soft deadline         hard deadline
	// |-------------------------|--------< buffer >---------|
	softDeadlineDuration = 30 * time.Second

	// set up our slow Slack mock
	mockOutputClient.On("Slack", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(15 * time.Second)
	}).Return(slowResponse).Maybe()

	// We get our results, but the DispachedAt timestamp is present
	// so we will ignore that for now
	dispatchStatusesResult := sendAlerts(expiredCtx, alertOutputMap, outputClient)

	mockOutputClient.AssertExpectations(t)

	modifiedDispatchStatusesResult := []DispatchStatus{}
	for _, dispatchStatus := range dispatchStatusesResult {
		newStatus := DispatchStatus{
			Alert:      dispatchStatus.Alert,
			OutputID:   dispatchStatus.OutputID,
			Message:    dispatchStatus.Message,
			StatusCode: dispatchStatus.StatusCode,
			Success:    dispatchStatus.Success,
			NeedsRetry: dispatchStatus.NeedsRetry,
			// This is calculated internally and is tough to
			// predict due to async threads. However, for the
			// sake of this test, we don't need to test
			// for timestamp equivalence. We only need to check
			// for the other fields.
			// DispatchedAt: dispatchStatus.DispatchedAt,
		}
		modifiedDispatchStatusesResult = append(modifiedDispatchStatusesResult, newStatus)
	}
	assert.Equal(t, len(expectedDispatchStatuses), len(modifiedDispatchStatusesResult))

	// since the result could be out of order, we need check for item equivalence and not the order
	equalDispatchCount := 0
	for _, expStatus := range expectedDispatchStatuses {
		for _, status := range modifiedDispatchStatusesResult {
			if expStatus.OutputID == status.OutputID {
				assert.Equal(t, expStatus, status)
				equalDispatchCount++
			}
		}
	}
	assert.Equal(t, 3, equalDispatchCount)
}
