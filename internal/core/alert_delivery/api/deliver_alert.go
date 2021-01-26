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
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertTable "github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Create generic resonse to be sent to the frontend. We log detailed info to CW.
const genericErrorMessage = "Could not find the rule associated with this alert!"

// DeliverAlert sends a specific alert to the specified destinations.
func (API) DeliverAlert(ctx context.Context, input *deliverymodel.DeliverAlertInput) (*deliverymodel.DeliverAlertOutput, error) {
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
	dispatchStatuses := sendAlerts(ctx, alertOutputMap, outputClient)

	// Record the delivery statuses to ddb
	alertSummaries := updateAlerts(dispatchStatuses)
	zap.L().Debug("Finished updating alert delivery statuses")

	alertSummary := alertSummaries[0]
	genericapi.ReplaceMapSliceNils(alertSummary)
	return alertSummary, nil
}

// getAlert - extracts the alert from the input payload and handles corner cases
func getAlert(input *deliverymodel.DeliverAlertInput) (*alertTable.AlertItem, error) {
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
func populateAlertData(alertItem *alertTable.AlertItem) (*deliverymodel.Alert, error) {
	switch alertItem.Type {
	case deliverymodel.PolicyType:
		return populateAlertWithPolicyData(alertItem)
	case deliverymodel.RuleType, deliverymodel.RuleErrorType:
		return populateAlertWithRuleData(alertItem)
	default:
		return nil, errors.Errorf("unknown alert type %s", alertItem.Type)
	}
}

func populateAlertWithPolicyData(alertItem *alertTable.AlertItem) (*deliverymodel.Alert, error) {
	commonFields := []zap.Field{
		zap.String("alertId", alertItem.AlertID),
		zap.String("policyId", alertItem.PolicyID),
		zap.String("policyVersion", alertItem.PolicyVersion),
	}

	getPolicyInput := analysismodels.LambdaInput{
		GetPolicy: &analysismodels.GetPolicyInput{
			ID:        alertItem.PolicyID,
			VersionID: alertItem.PolicyVersion,
		},
	}
	var policy analysismodels.Policy
	if _, err := analysisClient.Invoke(&getPolicyInput, &policy); err != nil {
		zap.L().Error("Error retrieving policy", append(commonFields, zap.Error(err))...)
		return nil, &genericapi.InternalError{Message: genericErrorMessage}
	}

	return &deliverymodel.Alert{
		AnalysisID:          policy.ID,
		Type:                deliverymodel.PolicyType,
		CreatedAt:           alertItem.CreationTime,
		Severity:            alertItem.Severity,
		OutputIds:           []string{}, // We do not pay attention to this field
		AnalysisDescription: aws.StringValue(alertItem.Description),
		AnalysisName:        aws.String(policy.DisplayName),
		Version:             &alertItem.PolicyVersion,
		Reference:           aws.StringValue(alertItem.Reference),
		Runbook:             aws.StringValue(alertItem.Runbook),
		Destinations:        alertItem.Destinations,
		Tags:                policy.Tags,
		AlertID:             &alertItem.AlertID,
		Title:               alertItem.Title,
		RetryCount:          0,
		IsTest:              false,
		IsResent:            true,
	}, nil
}

func populateAlertWithRuleData(alertItem *alertTable.AlertItem) (*deliverymodel.Alert, error) {
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

	return &deliverymodel.Alert{
		AnalysisID:          rule.ID,
		Type:                deliverymodel.RuleType,
		CreatedAt:           alertItem.CreationTime,
		Severity:            alertItem.Severity,
		OutputIds:           []string{}, // We do not pay attention to this field
		AnalysisDescription: aws.StringValue(alertItem.Description),
		AnalysisName:        aws.String(rule.DisplayName),
		Version:             &alertItem.RuleVersion,
		Reference:           aws.StringValue(alertItem.Reference),
		Runbook:             aws.StringValue(alertItem.Runbook),
		Destinations:        alertItem.Destinations,
		Tags:                rule.Tags,
		AlertID:             &alertItem.AlertID,
		Title:               alertItem.Title,
		RetryCount:          0,
		IsTest:              false,
		IsResent:            true,
	}, nil
}

// getAlertOutputMapping - gets a map for a given alert to it's outputIds
func getAlertOutputMapping(alert *deliverymodel.Alert, outputIds []string) (AlertOutputMap, error) {
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

	// Check the provided the input outputIds and generate a list of valid outputs.
	validOutputIds := intersection(outputIds, outputs)
	if len(validOutputIds) == 0 {
		return alertOutputMap, &genericapi.InvalidInputError{
			Message: "Invalid destination(s) specified: " + strings.Join(outputIds, ", ")}
	}

	// Next, we filter out any outputs that don't match the Alert Type setting
	filteredOutputs := filterOutputsByAlertType(alert, validOutputIds)

	// If there's a difference, return an error message with the IDs that failed
	diffOutputs := difference(validOutputIds, filteredOutputs)
	if len(diffOutputs) > 0 {
		diffOutputIds := []string{}
		for _, out := range diffOutputs {
			diffOutputIds = append(diffOutputIds, *out.OutputID)
		}

		return alertOutputMap, &genericapi.InvalidInputError{
			Message: fmt.Sprintf("The destination(s) specified do not accept this Alert's Type: [%s])", strings.Join(diffOutputIds, ", "))}
	}

	// Map the outputs
	alertOutputMap[alert] = filteredOutputs
	return alertOutputMap, nil
}

// intersection - Finds the intersection O(M + N) of a list of strings and outputs: A ∩ B
func intersection(a []string, b []*outputModels.AlertOutput) []*outputModels.AlertOutput {
	m := make(map[string]struct{})

	for _, item := range a {
		m[item] = struct{}{}
	}

	res := make([]*outputModels.AlertOutput, 0)
	for _, item := range b {
		if _, ok := m[*item.OutputID]; ok {
			res = append(res, item)
		}
	}

	return res
}

// difference - Finds the difference O(M + N) of outputs: A - B
func difference(a, b []*outputModels.AlertOutput) []*outputModels.AlertOutput {
	m := make(map[string]struct{})

	for _, item := range a {
		m[*item.OutputID] = struct{}{}
	}

	res := make([]*outputModels.AlertOutput, 0)
	for _, item := range b {
		if _, ok := m[*item.OutputID]; !ok {
			res = append(res, item)
		}
	}
	return res
}
