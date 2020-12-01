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

// Exceptions is a a GitLab log line from a failed interaction with git
// nolint: lll
type Exceptions struct {
	Severity           pantherlog.String `json:"severity" validate:"required" description:"The log level"`
	Time               pantherlog.Time   `json:"time" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The event timestamp"`
	CorrelationID      pantherlog.String `json:"correlation_id" panther:"trace_id" description:"Request unique id across logs"`
	ExtraServer        *ExtraServer      `json:"extra.server" description:"Information about the server on which the exception occurred"`
	ExtraProjectID     pantherlog.Int64  `json:"extra.project_id" description:"Project id where the exception occurred"`
	ExtraRelationKey   pantherlog.String `json:"extra.relation_key" description:"Relation on which the exception occurred"`
	ExtraRelationIndex pantherlog.Int64  `json:"extra.relation_index" description:"Relation index on which the exception occurred"`
	ExceptionClass     pantherlog.String `json:"exception.class" validate:"required" description:"Class name of the exception that occurred"`
	ExceptionMessage   pantherlog.String `json:"exception.message" validate:"required" description:"Message of the exception that occurred"`
	ExceptionBacktrace []string          `json:"exception.backtrace" description:"Stack trace of the exception that occurred"`
}

// ExtraServer has info about the server an exception occurred
type ExtraServer struct {
	OS      *ServerOS      `json:"os" validation:"required" description:"Server OS info"`
	Runtime *ServerRuntime `json:"runtime" validation:"required" description:"Runtime executing gitlab code"`
}

// ServerRuntime has info about the runtime where an exception occurred
type ServerRuntime struct {
	Name    pantherlog.String `json:"name" validation:"required" description:"Runtime name"`
	Version pantherlog.String `json:"version" validation:"required" description:"Runtime version"`
}

// ServerOS has info about the OS where an exception occurred
type ServerOS struct {
	Name    pantherlog.String `json:"name" validation:"required" description:"OS name"`
	Version pantherlog.String `json:"version" validation:"required" description:"OS version"`
	Build   pantherlog.String `json:"build" validation:"required" description:"OS build"`
}
