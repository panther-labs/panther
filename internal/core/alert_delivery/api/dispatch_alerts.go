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

	"github.com/go-playground/validator"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
)

// DispatchAlerts - Sends an alert to sends a specific alert to the specified destinations.
func (API) DispatchAlerts(ctx context.Context, input []*deliverymodel.DispatchAlertsInput) (interface{}, error) {
	zap.L().Debug("Dispatching alerts", zap.Int("num_alerts", len(input)))

	// Extract alerts from the input payload
	alerts := getAlerts(input)

	zap.L().Debug("Extracted from input", zap.Any("alerts", alerts))

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMap(alerts)
	if err != nil {
		return nil, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := sendAlerts(ctx, alertOutputMap, outputClient)

	// Record the delivery statuses to ddb. Ignore the returned output.
	updateAlerts(dispatchStatuses)
	zap.L().Debug("Finished updating alert delivery statuses")

	success, failed := filterDispatches(dispatchStatuses)
	zap.L().Debug("Deliveries that failed", zap.Int("num_failed", len(failed)))
	zap.L().Debug("Deliveries that succeeded", zap.Int("num_success", len(success)))

	// Obtain a list of alerts that should be retried and put back on to the queue
	alertsToRetry := getAlertsToRetry(failed, env.AlertRetryCount)

	// Put any alerts that need to be retried back into the queue
	retry(alertsToRetry, env.AlertQueueURL, env.MinRetryDelaySecs, env.MaxRetryDelaySecs)

	return nil, err
}

// getAlerts - extracts the alerts from an DispatchAlertsInput (SQSMessage)
func getAlerts(input []*deliverymodel.DispatchAlertsInput) []*deliverymodel.Alert {
	alerts := []*deliverymodel.Alert{}
	validate := validator.New()

	for _, record := range input {
		alert := &deliverymodel.Alert{}
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

// getAlertOutputMap - maps a list of alerts to their specified destinations or defaults
func getAlertOutputMap(alerts []*deliverymodel.Alert) (AlertOutputMap, error) {
	// Create our Alert -> Output mappings
	alertOutputMap := make(AlertOutputMap)
	for _, alert := range alerts {
		// We get a list of outputs depending on several dynamic factors
		outputs, err := getAlertOutputs(alert)
		if err != nil {
			return alertOutputMap, errors.Wrapf(err, "Failed to fetch outputIds")
		}

		// Finally, assign the alert to the set of unique outputs
		alertOutputMap[alert] = outputs
	}
	return alertOutputMap, nil
}

// filterDispatches - returns a tuple (success, failed) of lists containing dispatch statuses
func filterDispatches(dispatchStatuses []DispatchStatus) ([]DispatchStatus, []DispatchStatus) {
	successDispatches := []DispatchStatus{}
	failedDispatches := []DispatchStatus{}
	for _, status := range dispatchStatuses {
		if !status.Success {
			failedDispatches = append(failedDispatches, status)
			continue
		}
		successDispatches = append(successDispatches, status)
	}
	return successDispatches, failedDispatches
}

// getAlertsToRetry - finds failed deliveries and generates a list of alerts that need to be retried.
//
// Note: If a single alert had 10 outputs (destinations -or- default outputs) and
// failed to be delivered to 3 of them, this function will return a list
// containing 3 alerts (in this case, the same alert) each with its outputIds
// list containing only the specific failed outputId.
//
// Previously, we put all the failed outputIds back into a single alert to be retried; however
// because the new mechanism tracks a single counter inside the alert itself, failures should be individually
// retried to track which destinations are failing.
//
// Ex:
// A list of alerts ([]*deliverymodel.Alert)
//   [
//   	{
//   		"alertID": "abc",
//   		...
//   		"outputIds": ["failed-output-id-1"]
//   	},
//   	{
//   		"alertID": "abc",
//   		...
//   		"outputIds": ["failed-output-id-2"]
//   	},
//   	{
//   		"alertID": "abc",
//   		...
//   		"outputIds": ["failed-output-id-3"]
//   	},
//   ]
//
func getAlertsToRetry(failedDispatchStatuses []DispatchStatus, maximumRetryCount int) []*deliverymodel.Alert {
	alertsToRetry := []*deliverymodel.Alert{}
	for _, failed := range failedDispatchStatuses {
		// If we've reached the max retry count for a specific alert, log and continue
		//
		// Note: This does not block the alert from being sent to other outputs because
		// when the alert is put back onto the queue, the outputIds will only have 1
		// destination specified.
		if failed.Alert.RetryCount >= maximumRetryCount {
			zap.L().Error(
				"alert delivery permanently failed, exceeded max retry count",
				zap.Any("status", failed),
			)
			continue
		}

		// If there was a permanent failure, log and don't retry
		if !failed.NeedsRetry {
			zap.L().Error(
				"permanently failed to send alert to output",
				zap.Any("status", failed),
			)
			continue
		}

		// Log that we will send this alert to be retried
		zap.L().Warn("will retry delivery of alert",
			zap.Any("status", failed),
		)

		// Create a shallow copy to mutate
		mutatedAlert := failed.Alert
		// Increment the retry counter in the alert
		mutatedAlert.RetryCount++
		// Overwrite the list of outputs with the output that failed
		mutatedAlert.OutputIds = []string{failed.OutputID}
		// Add the alert in question to a new list to be retried
		alertsToRetry = append(alertsToRetry, &mutatedAlert)
	}
	return alertsToRetry
}
