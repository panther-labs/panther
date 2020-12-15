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

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/utils"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateAlertDelivery modifies an alert's attributes.
func (api *API) UpdateAlertDelivery(input *models.UpdateAlertDeliveryInput) (result *models.UpdateAlertDeliveryOutput, err error) {
	// Run the update alert query
	alertItem, err := api.alertsDB.UpdateAlertDelivery(input)
	if err != nil {
		return nil, err
	}

	// If there was no item from the DB, we return an empty response
	if alertItem == nil {
		return &models.UpdateAlertDeliveryOutput{}, nil
	}

	alertRule, err := api.ruleCache.Get(alertItem.RuleID, alertItem.RuleVersion)

	if err != nil {
		zap.L().Warn("failed to get rule with ID", zap.Any("rule id", alertItem.RuleID),
			zap.Any("rule version", alertItem.RuleVersion), zap.Any("error", err))
	}

	// Marshal to an alert summary
	result = utils.AlertItemToSummary(alertItem, alertRule)

	genericapi.ReplaceMapSliceNils(result)
	return result, nil
}
