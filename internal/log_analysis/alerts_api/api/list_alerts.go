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
	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ListAlerts retrieves alert and event details.
func (API) ListAlerts(input *models.ListAlertsInput) (result *models.ListAlertsOutput, err error) {
	result = &models.ListAlertsOutput{}
	var alertItems []*table.AlertItem

	// Perform some validation here for items that do not have custom validators implemented
	if input.CreatedAtAfter != nil && input.CreatedAtBefore != nil && input.CreatedAtBefore.Before(*input.CreatedAtAfter) {
		return nil, &genericapi.InternalError{Message: "Invalid range, created at 'before' must be greater than 'after'"}
	}

	if input.EventCountMax != nil && input.EventCountMin != nil && *input.EventCountMax < *input.EventCountMin {
		return nil, &genericapi.InternalError{Message: "Invalid range, event count 'max' must be greater or equal to 'min'"}
	}

	// Fetch all alerts. The results will have filters, sorting applied.
	alertItems, result.LastEvaluatedKey, err = alertsDB.ListAll(input)

	if err != nil {
		return nil, err
	}

	result.Alerts = alertItemsToAlertSummary(alertItems)

	gatewayapi.ReplaceMapSliceNils(result)
	return result, nil
}

// alertItemsToAlertSummary converts a list of DDB AlertItem(s) to AlertSummary(ies)
func alertItemsToAlertSummary(items []*table.AlertItem) []*models.AlertSummary {
	result := make([]*models.AlertSummary, len(items))

	for i, item := range items {
		result[i] = alertItemToAlertSummary(item)
	}

	return result
}

// alertItemToAlertSummary converts a DDB AlertItem to an AlertSummary
func alertItemToAlertSummary(item *table.AlertItem) *models.AlertSummary {
	return &models.AlertSummary{
		AlertID:         &item.AlertID,
		CreationTime:    &item.CreationTime,
		DedupString:     &item.DedupString,
		EventsMatched:   &item.EventCount,
		RuleDisplayName: item.RuleDisplayName,
		RuleID:          &item.RuleID,
		RuleVersion:     &item.RuleVersion,
		Severity:        &item.Severity,
		Status:          &item.Status,
		Title:           getAlertTitle(item),
		UpdatedBy:       &item.UpdatedBy,
		UpdatedByTime:   &item.UpdatedByTime,
		UpdateTime:      &item.UpdateTime,
	}
}
