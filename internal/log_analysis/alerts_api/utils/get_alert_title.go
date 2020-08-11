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
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

// GetAlertTitle - Method required for backwards compatibility
// In case the alert title is empty, return custom title
func (utils *AlertUtils) GetAlertTitle(alert *table.AlertItem) *string {
	if alert.Title != nil {
		return alert.Title
	}
	if alert.RuleDisplayName != nil {
		return alert.RuleDisplayName
	}
	return &alert.RuleID
}
