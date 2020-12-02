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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertTable "github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Create generic resonse to be sent to the frontend. We log detailed info to CW.
const genericErrorMessage = "Could not find the rule associated with this alert!"

// DeliverAlert sends a specific alert to the specified destinations.
func (API) DeliverAlert(input *deliveryModels.DeliverAlertInput) (*deliveryModels.DeliverAlertOutput, error) {
	// First, fetch the alert
	zap.L().Debug("Fetching alert", zap.String("AlertID", input.AlertID))

	// Extract the alert from the input and lookup from ddb
	alertItem, err := getAlert(input)
	if err != nil {
		return nil, err
	}
	// Fetch the Policy or Rule associated with the alert to fill in the missing attributes
	alert, err := populateAlertData(alertItem)
	if err != nil {
		return nil, err
	}

	// Get our Alert -> Output mappings. We determine which destinations an alert should be sent.
	alertOutputMap, err := getAlertOutputMapping(alert, input.OutputIds)

	if err != nil {
		return nil, err
	}

	// Send alerts to the specified destination(s) and obtain each response status
	dispatchStatuses := sendAlerts(alertOutputMap)

	// Record the delivery statuses to ddb
	alertSummaries := updateAlerts(dispatchStatuses)
	zap.L().Debug("Finished updating alert delivery statuses")

	alertSummary := alertSummaries[0]
	genericapi.ReplaceMapSliceNils(alertSummary)
	return alertSummary, nil
}

// getAlert - extracts the alert from the input payload and handles corner cases
func getAlert(input *deliveryModels.DeliverAlertInput) (*alertTable.AlertItem, error) {
	alertItem, err := alertsTableClient.GetAlert(input.AlertID)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to fetch alert %s from ddb", input.AlertID)
	}

	// If the alertId was not found, log and return
	if alertItem == nil {
		return nil, &genericapi.DoesNotExistError{
			Message: "Unable to find the specified alert: " + input.AlertID}
	}
	return alertItem, nil
}

// populateAlertData - queries the rule associated and merges in the details to the alert
func populateAlertData(alertItem *alertTable.AlertItem) (*deliveryModels.Alert, error) {
	commonFields := []zap.Field{
		zap.String("alertId", alertItem.AlertID),
		zap.String("ruleId", alertItem.RuleID),
		zap.String("ruleVersion", alertItem.RuleVersion),
	}

	getRuleInput := analysismodels.LambdaInput{
		GetRule: &analysismodels.GetRuleInput{
			ID:        alertItem.RuleID,
			VersionID: alertItem.RuleVersion,
		},
	}
	var rule analysismodels.Rule
	if _, err := analysisClient.Invoke(&getRuleInput, &rule); err != nil {
		zap.L().Error("Error retrieving rule", append(commonFields, zap.Error(err))...)
		return nil, &genericapi.InternalError{Message: genericErrorMessage}
	}

	return &deliveryModels.Alert{
		AnalysisID:          rule.ID,
		Type:                deliveryModels.RuleType,
		CreatedAt:           alertItem.CreationTime,
		Severity:            alertItem.Severity,
		OutputIds:           []string{}, // We do not pay attention to this field
		AnalysisDescription: alertItem.Description,
		AnalysisName:        aws.String(rule.DisplayName),
		Version:             &alertItem.RuleVersion,
		Reference:           alertItem.Reference,
		Runbook:             alertItem.Runbook,
		DestinationOverride: alertItem.DestinationOverride,
		Tags:                rule.Tags,
		AlertID:             &alertItem.AlertID,
		Title:               alertItem.Title,
		RetryCount:          0,
		IsTest:              false,
		IsResent:            true,
	}, nil
}

// getAlertOutputMapping - gets a map for a given alert to it's outputIds
func getAlertOutputMapping(alert *deliveryModels.Alert, outputIds []string) (AlertOutputMap, error) {
	// Initialize our Alert -> Output map
	alertOutputMap := make(AlertOutputMap)

	// This function is used for the HTTP API and we always need
	// to fetch the latest outputs instead of using a cache.
	// The only time we use cached values is when the lambda
	// is triggered by an SQS event.
	outputsCache.setExpiry(time.Now().Add(time.Minute * time.Duration(-5)))

	// Fetch outputIds from ddb
	outputs, err := getOutputs()
	if err != nil {
		return alertOutputMap, errors.Wrapf(err, "Failed to fetch outputIds")
	}

	// Check the provided the input outputIds and generate a list of valid outputs
	validOutputIds := intersection(outputIds, outputs)
	if len(validOutputIds) == 0 {
		return alertOutputMap, &genericapi.InvalidInputError{
			Message: "Invalid destination(s) specified: " + strings.Join(outputIds, ", ")}
	}

	// Map the outputs
	alertOutputMap[alert] = validOutputIds
	return alertOutputMap, nil
}

// intersection - Finds the intersection O(M + N) of panther outputs and the provided input list of outputIds
func intersection(inputs []string, outputs []*outputModels.AlertOutput) []*outputModels.AlertOutput {
	m := make(map[string]struct{})

	for _, item := range inputs {
		m[item] = struct{}{}
	}

	valid := make([]*outputModels.AlertOutput, 0, len(outputs))
	for _, item := range outputs {
		if _, ok := m[*item.OutputID]; ok {
			valid = append(valid, item)
		}
	}

	return valid
}
