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
	"go.uber.org/zap"

	alertmodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
)

// OutputStatus communicates parallelized alert delivery status via channels.
type OutputStatus struct {
	OutputID   string
	Message    string
	Success    bool
	NeedsRetry bool
}

// Send an alert to one specific output (run as a child goroutine).
//
// The statusChannel will be sent a message with the result of the send attempt.
func send(alert *alertmodels.Alert, output *outputmodels.AlertOutput, statusChannel chan OutputStatus) {
	commonFields := []zap.Field{
		zap.String("outputID", *output.OutputID),
		zap.String("policyId", alert.AnalysisID),
	}

	defer func() {
		// If we panic when sending an alert, log an error and report back to the channel.
		// Otherwise, the main routine will wait forever for this to finish.
		if r := recover(); r != nil {
			zap.L().Error("panic sending alert", append(commonFields, zap.Any("panic", r))...)
			statusChannel <- OutputStatus{
				OutputID:   *output.OutputID,
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
		statusChannel <- OutputStatus{
			OutputID:   *output.OutputID,
			Success:    false,
			Message:    "unsupported output type",
			NeedsRetry: false,
		}
		return
	}

	if response == nil {
		zap.L().Warn("output response is nil", commonFields...)
		statusChannel <- OutputStatus{
			OutputID:   *output.OutputID,
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
	statusChannel <- OutputStatus{
		OutputID:   *output.OutputID,
		Success:    response.Success,
		Message:    response.Message,
		NeedsRetry: !response.Success && !response.Permanent,
	}
}

// Dispatch sends the alert to each of its designated outputs.
//
// Returns true if the alert was sent successfully, false if it needs to be retried.
func dispatch(alert *alertmodels.Alert) bool {
	alertOutputs, err := GetAlertOutputs(alert)

	if err != nil {
		zap.L().Warn("failed to get the outputs for the alert",
			zap.String("policyId", alert.AnalysisID),
			zap.String("severity", alert.Severity),
			zap.Error(err),
		)

		return false
	}

	if len(alertOutputs) == 0 {
		zap.L().Info("no outputs configured",
			zap.String("policyId", alert.AnalysisID),
			zap.String("severity", alert.Severity),
		)
		return true
	}

	// Dispatch all outputs in parallel.
	// This ensures one slow or failing output won't block the others.
	statusChannel := make(chan OutputStatus)
	for _, output := range alertOutputs {
		go send(alert, output, statusChannel)
	}

	// Wait until all outputs have finished, gathering any that need to be retried.
	var retryOutputs []string
	for range alertOutputs {
		status := <-statusChannel

		if status.NeedsRetry {
			retryOutputs = append(retryOutputs, status.OutputID)
		} else if !status.Success {
			zap.L().Error(
				"permanently failed to send alert to output",
				zap.String("outputID", status.OutputID),
			)
		}
	}

	if len(retryOutputs) > 0 {
		alert.OutputIds = retryOutputs // Replace the outputs with the set that failed
		return false
	}

	return true
}
