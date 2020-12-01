package gitlablogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// Git is a a GitLab log line from a failed interaction with git
type Git struct {
	Severity      pantherlog.String `json:"severity" validate:"required" description:"The log level"`
	Time          pantherlog.Time   `json:"time" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The event timestamp"`
	CorrelationID pantherlog.String `json:"correlation_id" panther:"trace_id" description:"Unique id across logs"`
	Message       pantherlog.String `json:"message" validate:"required" description:"The error message from git"`
}
