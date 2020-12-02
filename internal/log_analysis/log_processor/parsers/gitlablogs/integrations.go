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

// Integrations is a a GitLab log line from an integrated gitlab activity
type Integrations struct {
	Severity     pantherlog.String `json:"severity" validate:"required" description:"The log level"`
	Time         pantherlog.Time   `json:"time" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The event timestamp"`
	ServiceClass pantherlog.String `json:"service_class" validate:"required" description:"The class name of the integrated service"`
	ProjectID    pantherlog.Int64  `json:"project_id" validate:"required" description:"The project id the integration was running on"`
	ProjectPath  pantherlog.String `json:"project_path" validate:"required" description:"The project path the integration was running on"`
	Message      pantherlog.String `json:"message" validate:"required" description:"The log message from the service"`
	ClientURL    pantherlog.String `json:"client_url" panther:"url" validate:"required" description:"The client url of the service"`
	Error        pantherlog.String `json:"error" description:"The error name if an error has occurred"`
}
