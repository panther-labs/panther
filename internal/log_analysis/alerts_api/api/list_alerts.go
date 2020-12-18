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
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/utils"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ListAlerts retrieves alert and event details.
func (api *API) ListAlerts(input *models.ListAlertsInput) (result *models.ListAlertsOutput, err error) {
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
	alertItems, result.LastEvaluatedKey, err = api.alertsDB.ListAll(input)

	// Fetch all rules for alerts
	alertRules := api.getAlertRules(alertItems)
	if err != nil {
		return nil, err
	}

	result.Alerts = utils.AlertItemsToSummaries(alertItems, alertRules)

	genericapi.ReplaceMapSliceNils(result)
	return result, nil
}
