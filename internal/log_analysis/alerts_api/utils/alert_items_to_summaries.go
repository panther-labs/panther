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
	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

// AlertItemsToSummaries converts a list of DDB AlertItem(s) to AlertSummary(ies)
func (utils *AlertUtils) AlertItemsToSummaries(items []*table.AlertItem) []*models.AlertSummary {
	result := make([]*models.AlertSummary, len(items))

	for i, item := range items {
		result[i] = utils.AlertItemToAlertSummary(item)
	}

	return result
}
