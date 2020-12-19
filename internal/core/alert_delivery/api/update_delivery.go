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
	"go.uber.org/zap"

	alertModels "github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// updateAlerts - dispatches parallel lambda requests to update the alert statuses
func updateAlerts(statuses []DispatchStatus) []*alertModels.AlertSummary {
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
		alertMap[*status.Alert.AlertID] = append(alertMap[*status.Alert.AlertID], deliveryResponse)
	}

	// Init a channel
	alertSummaryChannel := make(chan alertModels.AlertSummary)

	// Make a lambda call for each alert in parallel. We dont make a single API call to reduce the failure impact.
	zap.L().Debug("Invoking UpdateAlertDelivery in parallel")

	for alertID, deliveryResponse := range alertMap {
		go updateAlert(alertID, deliveryResponse, alertSummaryChannel)
	}

	zap.L().Debug("Joining UpdateAlertDelivery results")
	// Join all goroutines and collect a list of summaries
	alertSummaries := []*alertModels.AlertSummary{}
	for range alertMap {
		alertSummary := <-alertSummaryChannel
		alertSummaries = append(alertSummaries, &alertSummary)
	}

	return alertSummaries
}

// updateAlert - invokes a lambda to update an alert's delivery status
func updateAlert(alertID string, deliveryResponse []*alertModels.DeliveryResponse, alertSummaryChannel chan alertModels.AlertSummary) {
	input := alertModels.LambdaInput{
		UpdateAlertDelivery: &alertModels.UpdateAlertDeliveryInput{
			AlertID:           alertID,
			DeliveryResponses: deliveryResponse,
		},
	}
	response := alertModels.UpdateAlertDeliveryOutput{}

	// We log, but do not return the error because this lambda execution needs to succeede regardless
	// if this invocation failed. By default, the genericapi will retry up to 3x before failure.
	if err := genericapi.Invoke(lambdaClient, env.AlertsAPI, &input, &response); err != nil {
		zap.L().Error("Invoking UpdateAlertDelivery failed", zap.Any("error", err))
	}
	alertSummaryChannel <- response
}
