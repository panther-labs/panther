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

	alertModels "github.com/panther-labs/panther/api/lambda/alerts/models"
	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Global variables
var (
	validate  = validator.New()
	alertsAPI = os.Getenv("ALERTS_API")
)

// DispatchAlerts - Sends an alert to sends a specific alert to the specified destinations.
func (API) DispatchAlerts(input []*deliveryModels.DispatchAlertsInput) (interface{}, error) {
	zap.L().Info("Dispatching alerts", zap.Int("num_alerts", len(input)))

	// Extract alerts from the input payload
	alerts := getAlerts(input)

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMap(alerts)
	if err != nil {
		return nil, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := sendAlerts(alertOutputMap)

	// TODO: Record the delivery statuses to ddb
	_, err = updateAlerts(dispatchStatuses)
	if err != nil {
		zap.L().Error("Updating Alert Delivery failed", zap.Any("error", err))
	}

	success, failed := filterDispatches(dispatchStatuses)
	zap.L().Info("Deliveries that failed", zap.Int("num_failed", len(failed)))
	zap.L().Info("Deliveries that succeeded", zap.Int("num_success", len(success)))

	// Obtain a list of alerts that should be retried and put back on to the queue
	alertsToRetry := getAlertsToRetry(alerts, failed)

	// Put any alerts that need to be retried back into the queue
	retry(alertsToRetry)

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
		validOutputIds, err := getAlertOutputs(alert)
		if err != nil {
			zap.L().Error("Failed to fetch outputIds", zap.Error(err))
			return nil, err
		}
		alertOutputMap[alert] = validOutputIds
	}
	return alertOutputMap, nil
}

// filterDispatches - returns a tuple (success, failed) of lists containing dispatch statuses
func filterDispatches(dispatchStatuses []DispatchStatus) ([]DispatchStatus, []DispatchStatus) {
	successDispatches := []DispatchStatus{}
	failedDispatches := []DispatchStatus{}
	for _, status := range dispatchStatuses {
		// Always warn of any generic failures
		if !status.Success {
			zap.L().Warn(
				"failed to send alert to output",
				zap.String("alertID", status.AlertID),
				zap.String("outputID", status.OutputID),
				zap.Int("statusCode", status.StatusCode),
				zap.String("message", status.Message),
			)
			failedDispatches = append(failedDispatches, status)
			continue
		}
		successDispatches = append(successDispatches, status)
	}
	return successDispatches, failedDispatches
}

// getAlertsToRetry - finds failed deliveries and generates a list of alerts that need to be retried.
//
// Note: If a single alert had 10 outputs (overrides -or- default outputs) and
// failed to be delivered to 3 of them, this function will return a list
// containing 3 alerts (in this case, the same alert) each with its outputIds
// list containing only the specific failed outputId.
//
// Ex:
// A list of alerts ([]*deliveryModels.Alert)
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
func getAlertsToRetry(alerts []*deliveryModels.Alert, failedDispatchStatuses []DispatchStatus) []*deliveryModels.Alert {
	alertsToRetry := []*deliveryModels.Alert{}
	for _, alert := range alerts {
		for _, failed := range failedDispatchStatuses {
			// Only look at alerts with matching delivery statuses
			if alert.AlertID != &failed.AlertID {
				continue
			}
			// If we've reached the max retry count for a specific alert, log and continue
			//
			// Note: This does not block the alert from being sent to other outputs because
			// when the alert is put back onto the queue, the outputIds will only have 1
			// destination specified.
			if alert.RetryCount >= maxRetryCount {
				zap.L().Error(
					"alert delivery permanently failed, exceeded max retry count",
					zap.String("alertID", *alert.AlertID),
					zap.String("outputId", failed.OutputID),
				)
				continue
			}

			// If there was a permanent failure, log and don't retry
			if !failed.NeedsRetry {
				zap.L().Error(
					"permanently failed to send alert to output",
					zap.String("alertID", *alert.AlertID),
					zap.String("outputID", failed.OutputID),
					zap.Int("statusCode", failed.StatusCode),
					zap.String("message", failed.Message),
				)
				continue
			}

			// Log that we will send this alert to be retried
			zap.L().Warn("will retry delivery of alert",
				zap.String("alertID", *alert.AlertID),
				zap.String("outputId", failed.OutputID),
			)

			// Create a shallow copy to mutate
			mutatedAlert := alert
			// Overwrite the list of outputs with the output that failed
			mutatedAlert.OutputIds = []string{failed.OutputID}
			// Add the alert in question to a new list to be retried
			alertsToRetry = append(alertsToRetry, mutatedAlert)
		}
	}
	return alertsToRetry
}

// updateAlerts - ivokes a lambda to update the alert statuses
func updateAlerts(statuses []DispatchStatus) ([]*alertModels.AlertSummary, error) {
	// create a relational mapping for alertID to a list of delivery statuses
	alertMap := make(map[string][]*alertModels.DeliveryResponse)
	for _, status := range statuses {
		// convert to the response type the lambda expects
		deliveryResponse := &alertModels.DeliveryResponse{
			OutputID:     status.OutputID,
			Message:      status.Message,
			StatusCode:   status.StatusCode,
			Success:      status.Success,
			DispatchedAt: status.DispatchedAt,
		}
		alertMap[status.AlertID] = append(alertMap[status.AlertID], deliveryResponse)
	}

	// Make a lambda call for each alert. We dont make a single API call to reduce the failure impact.
	responses := []*alertModels.UpdateAlertDeliveryOutput{}
	for alertID, deliveryResponse := range alertMap {
		input := alertModels.LambdaInput{UpdateAlertDelivery: &alertModels.UpdateAlertDeliveryInput{
			AlertID:           alertID,
			DeliveryResponses: deliveryResponse,
		}}
		var response alertModels.UpdateAlertDeliveryOutput
		if err := genericapi.Invoke(lambdaClient, alertsAPI, &input, &response); err != nil {
			zap.L().Error("Invoking UpdateAlertDelivery failed", zap.Any("error", err))
		}

		responses = append(responses, &response)
	}
	return responses, nil
}
