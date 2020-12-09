// Package utils manages all of the utility functions for alerts that are public
package utils

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"go.uber.org/zap"

	alertmodels "github.com/panther-labs/panther/api/lambda/alerts/models"
	alertdeliverymodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

var (
	awsSession   = session.Must(session.NewSession())
	lambdaClient = lambda.New(awsSession)

	analysisClient gatewayapi.API = gatewayapi.NewClient(lambdaClient, "panther-analysis-api")
)

// AlertItemsToSummaries converts a list of DDB AlertItem(s) to AlertSummary(ies)
func AlertItemsToSummaries(items []*table.AlertItem) []*alertmodels.AlertSummary {
	result := make([]*alertmodels.AlertSummary, len(items))

	for i, item := range items {
		result[i] = AlertItemToSummary(item)
	}

	return result
}

func getRule(resourceID string) (*analysismodels.Rule, error) {
	input := analysismodels.LambdaInput{
		GetRule: &analysismodels.GetRuleInput{ID: resourceID},
	}
	var result analysismodels.Rule
	if _, err := analysisClient.Invoke(&input, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AlertItemToSummary converts a DDB AlertItem to an AlertSummary
func AlertItemToSummary(item *table.AlertItem) *alertmodels.AlertSummary {
	// convert empty status to "OPEN" status
	alertStatus := item.Status
	if alertStatus == "" {
		alertStatus = alertmodels.OpenStatus
	}
	alertType := item.Type
	if len(alertType) == 0 {
		alertType = alertdeliverymodels.RuleType
	}

	// Generated Fields - backwards compatibility support
	// Check if we have a generated description, destination, runbook, reference, severity
	alertRule, err := getRule(item.AlertID)

	if err != nil {
		zap.L().Warn("Failed to get Rule with ID ", zap.String("AlertID", item.AlertID))
	}

	description, reference, runbook := item.Description, item.Reference, item.Runbook

	if description == "" && alertRule != nil {
		description = alertRule.Description
	}
	if reference == "" && alertRule != nil {
		reference = alertRule.Reference
	}
	if runbook == "" && alertRule != nil {
		runbook = alertRule.Runbook
	}

	return &alertmodels.AlertSummary{
		AlertID:           item.AlertID,
		Type:              alertType,
		CreationTime:      &item.CreationTime,
		DedupString:       &item.DedupString,
		EventsMatched:     &item.EventCount,
		RuleDisplayName:   item.RuleDisplayName,
		RuleID:            &item.RuleID,
		RuleVersion:       &item.RuleVersion,
		Severity:          aws.String(item.Severity),
		Status:            alertStatus,
		Title:             GetAlertTitle(item),
		LogTypes:          item.LogTypes,
		LastUpdatedBy:     item.LastUpdatedBy,
		LastUpdatedByTime: item.LastUpdatedByTime,
		UpdateTime:        &item.UpdateTime,
		DeliveryResponses: item.DeliveryResponses,
		PolicyID:          item.PolicyID,
		PolicyDisplayName: item.PolicyDisplayName,
		PolicySourceID:    item.PolicySourceID,
		PolicyVersion:     item.PolicyVersion,
		ResourceTypes:     item.ResourceTypes,
		ResourceID:        item.ResourceID,
		// Generated Fields Support
		Description: description,
		Reference:   reference,
		Runbook:     runbook,
	}
}

// GetAlertTitle - Method required for backwards compatibility
// In case the alert title is empty, return custom title
func GetAlertTitle(alert *table.AlertItem) *string {
	if alert.Title != "" {
		return aws.String(alert.Title)
	}
	if alert.Type != alertdeliverymodels.PolicyType {
		if alert.RuleDisplayName != nil {
			return alert.RuleDisplayName
		}
		return &alert.RuleID
	}
	if alert.ResourceID != "" {
		return &alert.ResourceID
	}
	if alert.PolicyDisplayName != "" {
		return &alert.PolicyDisplayName
	}
	return &alert.PolicyID
}
