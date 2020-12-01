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

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	alertdeliverymodels "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

// AlertItemsToSummaries converts a list of DDB AlertItem(s) to AlertSummary(ies)
func AlertItemsToSummaries(items []*table.AlertItem) []*models.AlertSummary {
	result := make([]*models.AlertSummary, len(items))

	for i, item := range items {
		result[i] = AlertItemToSummary(item)
	}

	return result
}

// AlertItemToSummary converts a DDB AlertItem to an AlertSummary
func AlertItemToSummary(item *table.AlertItem) *models.AlertSummary {
	// convert empty status to "OPEN" status
	alertStatus := item.Status
	if alertStatus == "" {
		alertStatus = models.OpenStatus
	}
	alertType := item.Type
	if len(alertType) == 0 {
		alertType = alertdeliverymodels.RuleType
	}

	return &models.AlertSummary{
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
	}
}

// GetAlertTitle - Method required for backwards compatibility
// In case the alert title is empty, return custom title
func GetAlertTitle(alert *table.AlertItem) *string {
	if alert.Title != "" {
		return aws.String(alert.Title)
	}
	if alert.RuleDisplayName != nil {
		return alert.RuleDisplayName
	}
	return &alert.RuleID
}
