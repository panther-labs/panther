package delivery

import (
	"go.uber.org/zap"

	alertmodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
)

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

// AlertOutputMap is a type alias for containing the outputIds that an alert should be delivered to
type AlertOutputMap map[*alertmodels.Alert][]*outputmodels.AlertOutput

// DispatchStatus holds info about which alert was sent to a given destination with its response status
type DispatchStatus struct {
	AlertID    string
	OutputID   string
	Message    string
	StatusCode int
	Success    bool
	NeedsRetry bool
}

// DeliverAlerts - dispatches alerts to their associated outputIds in parallel
func DeliverAlerts(alertOutputs AlertOutputMap) []DispatchStatus {
	// Initialize the channel to dispatch all outputs in parallel.
	statusChannel := make(chan DispatchStatus)

	// Extract the maps (k, v)
	for alert, outputIds := range alertOutputs {
		for _, output := range outputIds {
			go deliverAlert(alert, output, statusChannel)
		}
	}

	// Wait until all outputs have finished, gathering all the statuses of each delivery
	var deliveryStatuses []DispatchStatus
	for range alertOutputs {
		status := <-statusChannel
		deliveryStatuses = append(deliveryStatuses, status)
	}

	return deliveryStatuses
}

// Send an alert to one specific output (run as a child goroutine).
//
// The statusChannel will be sent a message with the result of the send attempt.
func deliverAlert(alert *alertmodels.Alert, output *outputmodels.AlertOutput, statusChannel chan DispatchStatus) {
	commonFields := []zap.Field{
		zap.String("alertID", *alert.AlertID),
		zap.String("outputID", *output.OutputID),
		zap.String("policyId", alert.AnalysisID),
	}

	defer func() {
		// If we panic when sending an alert, log an error and report back to the channel.
		// Otherwise, the main routine will wait forever for this to finish.
		if r := recover(); r != nil {
			zap.L().Error("panic sending alert", append(commonFields, zap.Any("panic", r))...)
			statusChannel <- DispatchStatus{
				AlertID:    *alert.AlertID,
				OutputID:   *output.OutputID,
				StatusCode: 500,
				Success:    false,
				Message:    "panic sending alert",
				NeedsRetry: false,
			}
		}
	}()

	zap.L().Info(
		"sending alert",
		append(commonFields, zap.String("name", *output.DisplayName))...,
	)
	var response *outputs.AlertDeliveryResponse
	switch *output.OutputType {
	case "slack":
		response = outputClient.Slack(alert, output.OutputConfig.Slack)
	case "pagerduty":
		response = outputClient.PagerDuty(alert, output.OutputConfig.PagerDuty)
	case "github":
		response = outputClient.Github(alert, output.OutputConfig.Github)
	case "opsgenie":
		response = outputClient.Opsgenie(alert, output.OutputConfig.Opsgenie)
	case "jira":
		response = outputClient.Jira(alert, output.OutputConfig.Jira)
	case "msteams":
		response = outputClient.MsTeams(alert, output.OutputConfig.MsTeams)
	case "sqs":
		response = outputClient.Sqs(alert, output.OutputConfig.Sqs)
	case "sns":
		response = outputClient.Sns(alert, output.OutputConfig.Sns)
	case "asana":
		response = outputClient.Asana(alert, output.OutputConfig.Asana)
	case "customwebhook":
		response = outputClient.CustomWebhook(alert, output.OutputConfig.CustomWebhook)
	default:
		zap.L().Warn("unsupported output type", commonFields...)
		statusChannel <- DispatchStatus{
			AlertID:    *alert.AlertID,
			OutputID:   *output.OutputID,
			StatusCode: 500,
			Success:    false,
			Message:    "unsupported output type",
			NeedsRetry: false,
		}
		return
	}

	if response == nil {
		zap.L().Warn("output response is nil", commonFields...)
		statusChannel <- DispatchStatus{
			AlertID:    *alert.AlertID,
			OutputID:   *output.OutputID,
			StatusCode: 500,
			Success:    false,
			Message:    "output response is nil",
			NeedsRetry: false,
		}
		return
	}

	if !response.Success {
		zap.L().Warn("failed to send alert", append(commonFields, zap.Error(response))...)
	} else {
		zap.L().Info("alert success", commonFields...)
	}

	// Retry only if not successful and we don't have a permanent failure
	statusChannel <- DispatchStatus{
		AlertID:    *alert.AlertID,
		OutputID:   *output.OutputID,
		StatusCode: response.StatusCode,
		Success:    response.Success,
		Message:    response.Message,
		NeedsRetry: !response.Success && !response.Permanent,
	}
}
