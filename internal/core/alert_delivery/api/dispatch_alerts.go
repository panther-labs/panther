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
	"fmt"
	"os"

	"github.com/go-playground/validator"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
)

var validate = validator.New()

// DispatchAlerts - Sends an alert to sends a specific alert to the specified destinations.
func (API) DispatchAlerts(input []*deliveryModels.DispatchAlertsInput) (output interface{}, err error) {
	zap.L().Info("Dispatching alerts", zap.Int("num_alerts", len(input)))

	// Extract alerts from the input payload
	alerts, err := getAlerts(input)
	if err != nil {
		return nil, err
	}

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMap(alerts)
	if err != nil {
		return nil, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := SendAlerts(alertOutputMap)

	// TODO: Record the delivery statuses to ddb
	// ...
	//

	// Obtain a list of alerts that should be retried and put back on to the queue
	alertsToRetry := getAlertsToRetry(alerts, dispatchStatuses, getMaxRetryCount())
	if len(alertsToRetry) > 0 {
		Retry(alertsToRetry)
	}

	return nil, err
}

func getAlerts(input []*deliveryModels.DispatchAlertsInput) (alerts []*deliveryModels.Alert, err error) {
	for _, record := range input {
		alert := &deliveryModels.Alert{}
		if err = jsoniter.UnmarshalFromString(record.Body, alert); err != nil {
			zap.L().Error("Failed to unmarshal item", zap.Error(err))
			continue
		}
		if err = validate.Struct(alert); err != nil {
			zap.L().Error("invalid message received", zap.Error(err))
			continue
		}
		alerts = append(alerts, alert)
	}
	return
}

func getAlertOutputMap(alerts []*deliveryModels.Alert) (alertOutputMap AlertOutputMap, err error) {
	// Create our Alert -> Output mappings
	alertOutputMap = make(AlertOutputMap)
	// Create a slice to be universal with the HTTP payload format
	for _, alert := range alerts {
		validOutputIds, err := GetAlertOutputs(alert)
		if err != nil {
			zap.L().Error("Failed to fetch outputIds", zap.Error(err))
			return nil, err
		}
		alertOutputMap[alert] = validOutputIds
	}
	return
}

func getAlertsToRetry(alerts []*deliveryModels.Alert, dispatchStatuses []DispatchStatus, maxRetryCount int) []*deliveryModels.Alert {
	alertsToRetry := []*deliveryModels.Alert{}
	for _, alert := range alerts {
		// If we've reached the max retry count for a specific alert, log a permanent failure
		if alert.RetryCount >= maxRetryCount {
			zap.L().Error(
				"alert delivery permanently failed, exceeded max retry count",
				zap.Strings("failedOutputs", alert.OutputIds),
				zap.Time("alertCreatedAt", alert.CreatedAt),
				zap.String("policyId", alert.AnalysisID),
				zap.String("severity", alert.Severity),
			)
			continue
		}

		fmt.Print(("Alert failed, will be retried..."))
		zap.L().Warn("will retry delivery of alert",
			zap.String("policyId", alert.AnalysisID),
			zap.String("severity", alert.Severity),
		)

		// Get a list of failed outputs for the alert
		outputsToRetry := getOutputsToRetry(alert, dispatchStatuses)
		if len(outputsToRetry) > 0 {
			// Create a shallow copy to mutate
			mutatedAlert := alert
			// Overwrite the slice of outputs
			mutatedAlert.OutputIds = outputsToRetry
			// Add the new alert to a new list to be retried
			alertsToRetry = append(alertsToRetry, mutatedAlert)
		}
	}
	return alertsToRetry
}

func getMaxRetryCount() int {
	return mustParseInt(os.Getenv("ALERT_RETRY_COUNT"))
}

func getOutputsToRetry(alert *deliveryModels.Alert, dispatchStatuses []DispatchStatus) (retryOutputs []string) {
	for _, delivery := range dispatchStatuses {
		// Skip deliveries not associated to our alert
		if delivery.AlertID != *alert.AlertID {
			continue
		}
		// Log any generic failures
		if !delivery.Success {
			zap.L().Error(
				"failed to send alert to output",
				zap.String("alertID", delivery.AlertID),
				zap.String("outputID", delivery.OutputID),
				zap.Int("statusCode", delivery.StatusCode),
				zap.String("message", delivery.Message),
			)
		}

		// Log permanent failures to be investigated
		if !delivery.Success && !delivery.NeedsRetry {
			zap.L().Error("permanently failed to send alert to output")
		}

		// Create a list of alerts to retry
		if !delivery.Success && delivery.NeedsRetry {
			retryOutputs = append(retryOutputs, delivery.OutputID)
		}
	}

	return
}
