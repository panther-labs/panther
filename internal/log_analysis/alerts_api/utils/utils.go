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
	analysismodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"go.uber.org/zap"
	"time"

	alertmodels "github.com/panther-labs/panther/api/lambda/alerts/models"
	alertdeliverymodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

// Used to cache a RuleID to an analysismodels.Rule & timestamp
var (
	ruleCache = make(map[ruleKey]cachedRule)
)

// Key used for the rule cache to map to a Rule
type ruleKey struct {
	RuleID string
}
type cachedRule struct {
	Rule      analysismodels.Rule
	Timestamp time.Time
}

func getRule(resourceID string, analysisClient gatewayapi.API) (*analysismodels.Rule, error) {
	// Key used to retrieve cached rule
	cacheKey := ruleKey{
		RuleID: resourceID,
	}

	// Return the cached short-lived rule (2 minutes)
	if cachedRule, exists := ruleCache[cacheKey]; exists {
		if time.Now().Add(-2 * time.Minute).Before(cachedRule.Timestamp) {
			zap.L().Debug("rule was cached", zap.Any("cache key", cacheKey))
			return &cachedRule.Rule, nil
		}
		zap.L().Debug("rule cache expired", zap.Any("cache key", cacheKey))
	}
	// Get the Rule
	input := analysismodels.LambdaInput{
		GetRule: &analysismodels.GetRuleInput{ID: resourceID},
	}
	var result analysismodels.Rule
	if _, err := analysisClient.Invoke(&input, &result); err != nil {
		return nil, err
	}
	// Cache and return rule
	ruleCache[cacheKey] = cachedRule{
		Rule:      result,
		Timestamp: time.Now(),
	}
	return &result, nil
}

// AlertItemsToSummaries converts a list of DDB AlertItem(s) to AlertSummary(ies)
func AlertItemsToSummaries(items []*table.AlertItem, analysisClient gatewayapi.API) []*alertmodels.AlertSummary {
	result := make([]*alertmodels.AlertSummary, len(items))

	for i, item := range items {
		result[i] = AlertItemToSummary(item, analysisClient)
	}

	return result
}

// AlertItemToSummary converts a DDB AlertItem to an AlertSummary
func AlertItemToSummary(item *table.AlertItem, analysisClient gatewayapi.API) *alertmodels.AlertSummary {
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
	description, reference, runbook := item.Description, item.Reference, item.Runbook

	// Check if we have these fields to avoid an unnecessary API call
	if aws.String(description) == nil || aws.String(reference) == nil || aws.String(runbook) == nil {
		alertRule, err := getRule(item.RuleID, analysisClient)
		if err != nil || alertRule == nil {
			zap.L().Warn("Failed to get Rule with ID ", zap.String("RuleID", item.RuleID))
		} else {
			if aws.String(description) == nil {
				description = alertRule.Description
			}
			if aws.String(reference) == nil {
				reference = alertRule.Reference
			}
			if aws.String(runbook) == nil {
				runbook = alertRule.Runbook
			}
		}
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
