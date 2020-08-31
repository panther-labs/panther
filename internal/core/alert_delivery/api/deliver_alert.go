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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertTable "github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// DeliverAlert sends a specific alert to the specified destinations.
func (API) DeliverAlert(input *deliveryModels.DeliverAlertInput) (*deliveryModels.DeliverAlertOutput, error) {
	// First, fetch the alert
	zap.L().Info("Fetching alert", zap.String("AlertID", input.AlertID))

	// Extract the alert from the input and lookup from ddb
	alertItem, err := getAlert(input)
	if err != nil {
		return nil, err
	}

	// Fetch the Policy or Rule associated with the alert to fill in the missing attributes
	alert := populateAlertData(alertItem)

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMapping(alert, input.OutputIds)
	if err != nil {
		return nil, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := sendAlerts(alertOutputMap)

	// Record the delivery statuses to ddb
	alertSummaries := updateAlerts(dispatchStatuses)
	zap.L().Info("Finished updating alert delivery statuses")

	// Log any failures and return
	if err := returnIfFailed(dispatchStatuses); err != nil {
		return nil, err
	}

	alertSummary := alertSummaries[0]
	gatewayapi.ReplaceMapSliceNils(alertSummary)
	return alertSummary, nil
}

// getAlert - extracts the alert from the input payload and handles corner cases
func getAlert(input *deliveryModels.DeliverAlertInput) (*alertTable.AlertItem, error) {
	alertItem, err := alertsTableClient.GetAlert(&input.AlertID)
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
func populateAlertData(alertItem *alertTable.AlertItem) *deliveryModels.Alert {
	// TODO: Fetch and merge the related fields from the Rule into the alert.
	// Alerts triggerd by Policies are not supported.
	// ...
	// Note: we need to account for the corner case when there is no rule
	// because it has been deleted. For now, we are taking the data from Dynamo
	// and populating as much as we have. Eventually, sending an alert should
	// be _exactly_ the same as if it were triggered by a Rule.
	return &deliveryModels.Alert{
		// AnalysisID: alertItem.AlertID,
		Type:      deliveryModels.RuleType, // For now, we hard-code this value as only RULE is supported
		CreatedAt: alertItem.CreationTime,
		Severity:  alertItem.Severity,
		OutputIds: alertItem.OutputIds,
		// AnalysisDescription: alertItem.Title,
		AnalysisName: alertItem.RuleDisplayName,
		Version:      &alertItem.RuleVersion,
		// Runbook:      alertItem.Runbook,
		// Tags:         alertItem.Tags,
		AlertID:    &alertItem.AlertID,
		Title:      aws.String("[re-sent] " + *alertItem.Title),
		RetryCount: 0,
	}
}

// getAlertOutputMapping - gets a map for a given alert to it's outputIds
func getAlertOutputMapping(alert *deliveryModels.Alert, outputIds []string) (AlertOutputMap, error) {
	// Initialize our Alert -> Output map
	alertOutputMap := make(AlertOutputMap)

	// Direct API hits should not use the cache. Only SQS events.
	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5)))

	// Fetch outputIds from ddb
	outputs, err := getOutputs()
	if err != nil {
		zap.L().Error("Failed to fetch outputIds", zap.Error(err))
		return alertOutputMap, err
	}

	// Check the provided the input outputIds and generate a list of valid outputs
	validOutputIds := intersection(outputIds, outputs)
	if len(validOutputIds) == 0 {
		zap.L().Error("Invalid outputIds specified", zap.Strings("OutputIds", outputIds))
		return alertOutputMap, &genericapi.InvalidInputError{
			Message: "Invalid destination(s) specified!"}
	}

	// Map the outputs
	alertOutputMap[alert] = validOutputIds
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

// returnIfFailed - logs failed deliveries and returns an error
func returnIfFailed(dispatchStatuses []DispatchStatus) error {
	shouldReturn := false
	for _, delivery := range dispatchStatuses {
		if !delivery.Success {
			zap.L().Error(
				"failed to send alert to output",
				zap.Any("alert", delivery.Alert),
				zap.String("outputID", delivery.OutputID),
				zap.Int("statusCode", delivery.StatusCode),
				zap.String("message", delivery.Message),
			)
			shouldReturn = true
		}
	}

	if shouldReturn {
		return &genericapi.InternalError{
			Message: "Some alerts failed to be delivered"}
	}

	return nil
}
