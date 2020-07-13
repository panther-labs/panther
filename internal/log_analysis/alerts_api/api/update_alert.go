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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateAlert modifies user attributes.
func (API) UpdateAlert(input *models.UpdateAlertInput) (result *models.UpdateAlertOutput, err error) {
	operation := common.OpLogManager.Start("updateAlert")
	defer func() {
		operation.Stop()
		operation.Log(err)
	}()

	// Perform input sanitization checks
	if input.AlertID == nil {
		return nil, &genericapi.InternalError{Message: "An AlerID must be specified"}
	}
	if input.Status == nil {
		return nil, &genericapi.InternalError{Message: "A Status must be specified"}
	}
	if input.RequesterID == nil {
		return nil, &genericapi.InternalError{Message: "A RequesterID must be specified"}
	}

	// Run the update alert query
	alertItem, err := alertsDB.UpdateAlert(input)
	if err != nil {
		return nil, err
	}

	// If there was no item from the DB, we return an empty response
	if alertItem == nil {
		return nil, nil
	}

	// Marshal to an alert summary
	result = &models.AlertSummary{
		AlertID:         &alertItem.AlertID,
		Status:          &alertItem.Status,
		RuleID:          &alertItem.RuleID,
		DedupString:     &alertItem.DedupString,
		CreationTime:    &alertItem.CreationTime,
		UpdateTime:      &alertItem.UpdateTime,
		EventsMatched:   &alertItem.EventCount,
		RuleDisplayName: alertItem.RuleDisplayName,
		Title:           getAlertTitle(alertItem),
		RuleVersion:     &alertItem.RuleVersion,
		Severity:        &alertItem.Severity,
		UpdatedBy:       &alertItem.UpdatedBy,
		UpdatedByTime:   &alertItem.UpdatedByTime,
	}

	gatewayapi.ReplaceMapSliceNils(result)
	return result, nil
}
