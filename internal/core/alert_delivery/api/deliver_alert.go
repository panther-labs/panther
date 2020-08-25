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

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// DeliverAlert sends a specific alert to the specified destinations.
func (API) DeliverAlert(input *deliveryModels.DeliverAlertInput) (*deliveryModels.DeliverAlertOutput, error) {
	// First, fetch the alert
	zap.L().Info("Fetching alert", zap.String("AlertID", input.AlertID))

	// Extract the alert from the input
	alertItem, err := getAlert(input)
	if err != nil {
		return nil, err
	}

	// Fetch the Policy or Rule associated with the alert to fill in the missing attributes
	alert := populateAlertData(alertItem)

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMapping(alert, input)
	if err != nil {
		return nil, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := sendAlerts(alertOutputMap)

	// Record the delivery statuses to ddb
	alertSummaries, err := updateAlerts(dispatchStatuses)
	if err != nil {
		return nil, err
	}
	zap.L().Info("Updated all alert delivery statuses successfully")

	// Because this API will be used for re-sending only 1 alert,
	// we log if there was a failure and return the error
	if err := logOrReturn(dispatchStatuses); err != nil {
		return nil, err
	}

	alertSummary := alertSummaries[0]
	gatewayapi.ReplaceMapSliceNils(alertSummary)
	return alertSummary, nil
}

// getAlert - extracts the alert from the input payload and handles corner cases
func getAlert(input *deliveryModels.DeliverAlertInput) (*table.AlertItem, error) {
	alertItem, err := alertsDB.GetAlert(&input.AlertID)
	if err != nil {
		zap.L().Error("Failed to fetch alert from ddb", zap.Error(err))
		return nil, err
	}

	// If the alertId was not found, log and return
	if alertItem == nil {
		zap.L().Error("Alert not found", zap.String("AlertID", input.AlertID))
		return nil, &genericapi.DoesNotExistError{
			Message: "Unable to find the specified alert!"}
	}
	return alertItem, nil
}

// populateAlertData - queries the rule or policy associated and merges in the details to the alert
func populateAlertData(alertItem *table.AlertItem) *deliveryModels.Alert {
	// TODO: Fetch and merge the related fields from the Policy/Rule into the alert.
	// ...
	// Note: we need to account for the corner case when there is no rule/policy
	// because it has been deleted. Additionally, we should provide an identifier
	// in the alert (TBD) to differentiate from re-send action or a new rule/policy trigger

	// For now, we are taking the data from Dynamo and populating as much as we have.
	// Eventually, sending an alert should be _exactly_ the same as if it were triggered
	// from a Policy or a Rule.
	return &deliveryModels.Alert{
		AnalysisID: alertItem.AlertID,
		Type:       "RULE",
		CreatedAt:  alertItem.CreationTime,
		Severity:   alertItem.Severity,
		OutputIds:  alertItem.OutputIds,
		// AnalysisDescription: alertItem.Title,
		AnalysisName: alertItem.RuleDisplayName,
		Version:      &alertItem.RuleVersion,
		// Runbook:      alertItem.Runbook,
		// Tags:         alertItem.Tags,
		AlertID:    &alertItem.AlertID,
		Title:      alertItem.Title,
		RetryCount: 0,
	}
}

// getAlertOutputMapping -
func getAlertOutputMapping(alert *deliveryModels.Alert, input *deliveryModels.DeliverAlertInput) (AlertOutputMap, error) {
	// Fetch outputIds from ddb (utilizing a cache)
	outputs, err := getOutputs()
	if err != nil {
		zap.L().Error("Failed to fetch outputIds", zap.Error(err))
		return nil, err
	}

	// Check the provided the input outputIds and generate a list of valid outputs
	validOutputIds := intersection(input.OutputIds, outputs)
	if len(validOutputIds) == 0 {
		zap.L().Error("Invalid outputIds specified", zap.Strings("OutputIds", input.OutputIds))
		return nil, &genericapi.InvalidInputError{
			Message: "Invalid destination(s) specified!"}
	}

	// Initialize our Alert -> Output mappings
	alertOutputMap := make(AlertOutputMap)

	// Create a list to be universal with the SQS payload format
	// as they both eventually call a function that expects a list.
	alerts := []*deliveryModels.Alert{alert}
	for _, alert := range alerts {
		alertOutputMap[alert] = validOutputIds
	}

	return alertOutputMap, nil
}

// intersection - Finds the intersection O(M + N) of panther outputs and the provided input list of outputIds
func intersection(inputs []string, outputs []*outputModels.AlertOutput) []*outputModels.AlertOutput {
	m := make(map[string]bool)

	for _, item := range inputs {
		m[item] = true
	}

	valid := []*outputModels.AlertOutput{}
	for _, item := range outputs {
		if _, ok := m[*item.OutputID]; ok {
			valid = append(valid, item)
		}
	}

	return valid
}

// logOrReturn - logs and eagerly returns an error if any of the deliveries failed
func logOrReturn(dispatchStatuses []DispatchStatus) error {
	for _, delivery := range dispatchStatuses {
		if !delivery.Success {
			zap.L().Error(
				"failed to send alert to output",
				zap.String("alertID", delivery.AlertID),
				zap.String("outputID", delivery.OutputID),
				zap.Int("statusCode", delivery.StatusCode),
				zap.String("message", delivery.Message),
			)

			// return early if there was a failure.
			return &genericapi.InternalError{
				Message: "Some alerts failed to be delivered"}
		}
	}
	return nil
}
