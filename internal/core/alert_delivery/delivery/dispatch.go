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

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
)

// outputStatus communicates parallelized alert delivery status via channels.
type outputStatus struct {
	outputID   string
	success    bool
	needsRetry bool
}

// Send an alert to one specific output (run as a child goroutine).
//
// The statusChannel will be sent a message with the result of the send attempt.
func send(alert *alertmodels.Alert, output *outputmodels.AlertOutput, statusChannel chan outputStatus) {
	commonFields := []zap.Field{
		zap.String("outputID", *output.OutputID),
		zap.String("policyId", alert.AnalysisID),
	}
	defer func() {
		// If we panic when sending an alert, log an error and report back to the channel.
		// Otherwise, the main routine will wait forever for this to finish.
		if r := recover(); r != nil {
			zap.L().Error("panic sending alert", append(commonFields, zap.Any("panic", r))...)
			statusChannel <- outputStatus{outputID: *output.OutputID, success: false, needsRetry: false}
		}
	}()

	zap.L().Info(
		"sending alert",
		append(commonFields, zap.String("name", *output.DisplayName))...,
	)

	var alertDeliveryError *outputs.AlertDeliveryError
	switch *output.OutputType {
	case "slack":
		alertDeliveryError = outputClient.Slack(alert, output.OutputConfig.Slack)
	case "pagerduty":
		alertDeliveryError = outputClient.PagerDuty(alert, output.OutputConfig.PagerDuty)
	case "github":
		alertDeliveryError = outputClient.Github(alert, output.OutputConfig.Github)
	case "opsgenie":
		alertDeliveryError = outputClient.Opsgenie(alert, output.OutputConfig.Opsgenie)
	case "jira":
		alertDeliveryError = outputClient.Jira(alert, output.OutputConfig.Jira)
	case "msteams":
		alertDeliveryError = outputClient.MsTeams(alert, output.OutputConfig.MsTeams)
	case "sqs":
		alertDeliveryError = outputClient.Sqs(alert, output.OutputConfig.Sqs)
	case "sns":
		alertDeliveryError = outputClient.Sns(alert, output.OutputConfig.Sns)
	case "asana":
		alertDeliveryError = outputClient.Asana(alert, output.OutputConfig.Asana)
	case "customwebhook":
		alertDeliveryError = outputClient.CustomWebhook(alert, output.OutputConfig.CustomWebhook)
	default:
		zap.L().Warn("unsupported output type", commonFields...)
		statusChannel <- outputStatus{outputID: *output.OutputID, success: false, needsRetry: false}
		return
	}
	if alertDeliveryError != nil {
		zap.L().Warn("failed to send alert", append(commonFields, zap.Error(alertDeliveryError))...)
		statusChannel <- outputStatus{
			outputID: *output.OutputID, success: false, needsRetry: !alertDeliveryError.Permanent}
		return
	}

	zap.L().Info("alert success", commonFields...)
	statusChannel <- outputStatus{outputID: *output.OutputID, success: true, needsRetry: false}
}

// Dispatch sends the alert to each of its designated outputs.
//
// Returns true if the alert was sent successfully, false if it needs to be retried.
func dispatch(alert *alertmodels.Alert) bool {
	outputs, err := getAlertOutputs(alert)

	if err != nil {
		zap.L().Warn("failed to get the outputs for the alert",
			zap.String("policyId", alert.AnalysisID),
			zap.String("severity", alert.Severity),
			zap.Error(err),
		)
		return false
	}

	if len(outputs) == 0 {
		zap.L().Info("no outputs configured",
			zap.String("policyId", alert.AnalysisID),
			zap.String("severity", alert.Severity),
		)
		return true
	}

	// Dispatch all outputs in parallel.
	// This ensures one slow or failing output won't block the others.
	statusChannel := make(chan outputStatus)
	for _, output := range outputs {
		go send(alert, output, statusChannel)
	}

	// Wait until all outputs have finished, gathering any that need to be retried.
	var retryOutputs []string
	for range outputs {
		status := <-statusChannel
		if status.needsRetry {
			retryOutputs = append(retryOutputs, status.outputID)
		} else if !status.success {
			zap.L().Error(
				"permanently failed to send alert to output",
				zap.String("outputID", status.outputID),
			)
		}
	}

	if len(retryOutputs) > 0 {
		alert.OutputIDs = retryOutputs // Replace the outputs with the set that failed
		return false
	}

	return true
}
