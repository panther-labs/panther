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
	"time"

	"go.uber.org/zap"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
)

// AlertOutputMap is a type alias for containing the outputIds that an alert should be delivered to
type AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput

// DispatchStatus holds info about which alert was sent to a given destination with its response status
type DispatchStatus struct {
	Alert        deliverymodel.Alert
	OutputID     string
	Message      string
	StatusCode   int
	Success      bool
	NeedsRetry   bool
	DispatchedAt time.Time
}

// sendAlerts - dispatches alerts to their associated outputIds in parallel
func sendAlerts(
	ctx context.Context,
	alertOutputs AlertOutputMap,
	outputClient outputs.API,
) []DispatchStatus {

	// Create a new child context with the a deadline that will exit before the lambda times out.
	// This will be used to cancel any running goroutines
	deadlineInFuture, _ := ctx.Deadline()
	deadlineBuffer := deadlineInFuture.Add(-softDeadlineDuration)
	ctx, cancel := context.WithDeadline(ctx, deadlineBuffer)

	// Even though ctx will be expired, it is good practice to call its
	// cancellation function in any case. Failure to do so may keep the
	// context and its parent alive longer than necessary.
	defer cancel()

	// Initialize the channel to dispatch all outputs in parallel.
	statusChannel := make(chan DispatchStatus, 1)

	// Extract the maps (k, v)
	for alert, outputIds := range alertOutputs {
		for _, output := range outputIds {
			dispatchedAt := time.Now().UTC()
			go sendAlert(ctx, alert, output, dispatchedAt, statusChannel, outputClient)
		}
	}

	// Wait until all outputs have finished, gathering all the statuses of each delivery
	var deliveryStatuses []DispatchStatus
	for alert, outputIds := range alertOutputs {
		for _, outputID := range outputIds {
			// TODO: remove the select statement:
			// https://github.com/panther-labs/panther/pull/2296#discussion_r548471507
			// We race against a deadline
			select {
			case <-ctx.Done():
				// Calculate the time the alert was dispatched at
				dispatchedAt := time.Now().UTC()
				dispatchedAt.Add(-softDeadlineDuration)
				timeoutStatus := DispatchStatus{
					Alert:        *alert,
					OutputID:     *outputID.OutputID,
					Message:      "Timeout: the upstream service did not respond back in time",
					StatusCode:   504,
					Success:      false,
					NeedsRetry:   true,
					DispatchedAt: dispatchedAt,
				}
				deliveryStatuses = append(deliveryStatuses, timeoutStatus)
			case status := <-statusChannel:
				deliveryStatuses = append(deliveryStatuses, status)
			}
		}
	}

	return deliveryStatuses
}

// sendAlert an alert to one specific output (run as a child goroutine).
//
// The statusChannel will be sent a message with the result of the send attempt.
func sendAlert(
	ctx context.Context,
	alert *deliverymodel.Alert,
	output *outputModels.AlertOutput,
	dispatchedAt time.Time,
	statusChannel chan DispatchStatus,
	outputClient outputs.API,
) {

	commonFields := []zap.Field{
		zap.Stringp("alertID", alert.AlertID),
		zap.String("policyId", alert.AnalysisID),
		zap.Stringp("outputID", output.OutputID),
	}

	defer func() {
		// If we panic when sending an alert, log an error and report back to the channel.
		// Otherwise, the main routine will wait forever for this to finish.
		if r := recover(); r != nil {
			zap.L().Error("panic sending alert", append(commonFields, zap.Any("panic", r))...)
			statusChannel <- DispatchStatus{
				Alert:        *alert,
				OutputID:     *output.OutputID,
				StatusCode:   500,
				Success:      false,
				Message:      "panic sending alert",
				NeedsRetry:   false,
				DispatchedAt: dispatchedAt,
			}
		}
	}()

	response := (*outputs.AlertDeliveryResponse)(nil)
	switch *output.OutputType {
	case "slack":
		response = outputClient.Slack(ctx, alert, output.OutputConfig.Slack)
	case "pagerduty":
		response = outputClient.PagerDuty(ctx, alert, output.OutputConfig.PagerDuty)
	case "github":
		response = outputClient.Github(ctx, alert, output.OutputConfig.Github)
	case "opsgenie":
		response = outputClient.Opsgenie(ctx, alert, output.OutputConfig.Opsgenie)
	case "jira":
		response = outputClient.Jira(ctx, alert, output.OutputConfig.Jira)
	case "msteams":
		response = outputClient.MsTeams(ctx, alert, output.OutputConfig.MsTeams)
	case "sqs":
		response = outputClient.Sqs(ctx, alert, output.OutputConfig.Sqs)
	case "sns":
		response = outputClient.Sns(ctx, alert, output.OutputConfig.Sns)
	case "asana":
		response = outputClient.Asana(ctx, alert, output.OutputConfig.Asana)
	case "customwebhook":
		response = outputClient.CustomWebhook(ctx, alert, output.OutputConfig.CustomWebhook)
	default:
		zap.L().Warn("unsupported output type", commonFields...)
		statusChannel <- DispatchStatus{
			Alert:        *alert,
			OutputID:     *output.OutputID,
			StatusCode:   500,
			Success:      false,
			Message:      "unsupported output type",
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		}
		return
	}

	if response == nil {
		zap.L().Warn("output response is nil", commonFields...)
		statusChannel <- DispatchStatus{
			Alert:        *alert,
			OutputID:     *output.OutputID,
			StatusCode:   500,
			Success:      false,
			Message:      "output response is nil",
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		}
		return
	}

	// Retry only if not successful and we don't have a permanent failure
	statusChannel <- DispatchStatus{
		Alert:        *alert,
		OutputID:     *output.OutputID,
		StatusCode:   response.StatusCode,
		Success:      response.Success && !response.Permanent,
		Message:      response.Message,
		NeedsRetry:   !response.Success && !response.Permanent,
		DispatchedAt: dispatchedAt,
	}
}
