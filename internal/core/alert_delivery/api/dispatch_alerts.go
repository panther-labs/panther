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
	alerts := getAlerts(input)

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

	failedDispatches := filterFailedDispatches(dispatchStatuses)

	// Obtain a list of alerts that should be retried and put back on to the queue
	alertsToRetry := getAlertsToRetry(alerts, failedDispatches, getMaxRetryCount())
	if len(alertsToRetry) == 0 {
		zap.L().Info("All alerts dispatched successfully!", zap.Int("delivered", len(dispatchStatuses)))
	}

	// Put any alerts that need to be retried back into the queue
	Retry(alertsToRetry)

	return nil, err
}

// getAlerts - extracts the alerts from an DispatchAlertsInput (SQSMessage)
func getAlerts(input []*deliveryModels.DispatchAlertsInput) []*deliveryModels.Alert {
	alerts := []*deliveryModels.Alert{}
	for _, record := range input {
		alert := &deliveryModels.Alert{}
		if err := jsoniter.UnmarshalFromString(record.Body, alert); err != nil {
			zap.L().Error("Failed to unmarshal item", zap.Error(err))
			continue
		}
		if err := validate.Struct(alert); err != nil {
			zap.L().Error("invalid message received", zap.Error(err))
			continue
		}
		alerts = append(alerts, alert)
	}
	return alerts
}

// getAlertOutputMap - maps a list of alerts to their specified override outputs or defaults
func getAlertOutputMap(alerts []*deliveryModels.Alert) (AlertOutputMap, error) {
	// Create our Alert -> Output mappings
	alertOutputMap := make(AlertOutputMap)
	for _, alert := range alerts {
		validOutputIds, err := GetAlertOutputs(alert)
		if err != nil {
			zap.L().Error("Failed to fetch outputIds", zap.Error(err))
			return nil, err
		}
		alertOutputMap[alert] = validOutputIds
	}
	return alertOutputMap, nil
}

// filterFailedDispatches - returns the faild dispatches
func filterFailedDispatches(dispatchStatuses []DispatchStatus) []DispatchStatus {
	failedDispatches := []DispatchStatus{}
	for _, status := range dispatchStatuses {
		if !status.Success {
			// Always warn of any generic failures
			if !status.Success {
				zap.L().Warn(
					"failed to send alert to output",
					zap.String("alertID", status.AlertID),
					zap.String("outputID", status.OutputID),
					zap.Int("statusCode", status.StatusCode),
					zap.String("message", status.Message),
				)
			}
			failedDispatches = append(failedDispatches, status)
		}
	}
	return failedDispatches
}

// getAlertsToRetry - finds failed dliveries and generates a list of alerts that need to be retried.
//
// Ex: If a single alert had 10 outputs (overrides -or- default outputs) and failed to be delivered to 2 of them, this function
// will return a list containing two alerts (in this case, the same alert) with the outputIds field set to the specific failed outputId:
func getAlertsToRetry(alerts []*deliveryModels.Alert, failedDispatchStatuses []DispatchStatus, maxRetryCount int) []*deliveryModels.Alert {
	alertsToRetry := []*deliveryModels.Alert{}
	for _, alert := range alerts {
		for _, failed := range failedDispatchStatuses {
			// Only look at alerts with matching delivery statuses
			if alert.AlertID != &failed.AlertID {
				continue
			}
			// If we've reached the max retry count for a specific alert, log a permanent failure and continue
			//
			// This does not block the alert from being sent to other outputs because
			// when the alert is put back onto the queue, the outputIds will
			// only have 1 destination specified.
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

			// Get a list of failed outputs for the alert
			outputsToRetry := getOutputsToRetry(alert, failedDispatchStatuses)

			// More than one destination can fail for a given alert. Here we iterate and add them to a list to be retried individually
			for _, outputToRetry := range outputsToRetry {
				// Log that we will send this alert to be retried
				zap.L().Warn("will retry delivery of alert",
					zap.String("policyId", alert.AnalysisID),
					zap.String("severity", alert.Severity),
					zap.String("outputId", outputToRetry),
				)

				// Create a shallow copy to mutate
				mutatedAlert := alert
				// Overwrite the list of outputs with the specific output that failed
				mutatedAlert.OutputIds = []string{outputToRetry}
				// Add the alert in question with it's singular outputId to a new list to be retried
				alertsToRetry = append(alertsToRetry, mutatedAlert)
			}
		}
	}
	return alertsToRetry
}

// getOutputsToRetry - finds all the failed outputIds (for failed delivery) of a given alert
func getOutputsToRetry(alert *deliveryModels.Alert, failedDispatchStatuses []DispatchStatus) []string {
	retryOutputs := []string{}
	for _, failedDelivery := range failedDispatchStatuses {
		// Log permanent failures to be investigated, but don't retry
		if !failedDelivery.NeedsRetry {
			zap.L().Error(
				"permanently failed to send alert to output",
				zap.String("alertID", *alert.AlertID),
				zap.String("outputID", failedDelivery.OutputID),
				zap.Int("statusCode", failedDelivery.StatusCode),
				zap.String("message", failedDelivery.Message),
			)
			continue
		}

		// Create a list of alerts to retry
		retryOutputs = append(retryOutputs, failedDelivery.OutputID)
	}

	return retryOutputs
}

// getMaxRetryCount - reads the env variable for max retry count
func getMaxRetryCount() int {
	return mustParseInt(os.Getenv("ALERT_RETRY_COUNT"))
}
