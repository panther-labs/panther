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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// TypeExceptions is the log type of Exceptions log records
const TypeExceptions = PantherPrefix + ".Exceptions"

// ExceptionsDesc describes the Git log record
var ExceptionsDesc = `GitLab log file containing changes to group or project settings 
Reference: https://docs.gitlab.com/ee/administration/logs.html#exceptions_jsonlog`

// Exceptions is a a GitLab log line from a failed interaction with git
// nolint: lll
type Exceptions struct {
	Severity           *string            `json:"severity" validate:"required" description:"The log level"`
	Time               *timestamp.RFC3339 `json:"time" validate:"required" description:"The event timestamp"`
	CorrelationID      *string            `json:"correlation_id,omitempty" description:"Request unique id across logs"`
	ExtraServer        *ExtraServer       `json:"extra.server,omitempty" description:"Information about the server on which the exception occurred"`
	ExtraProjectID     *int64             `json:"extra.project_id,omitempty" description:"Project id where the exception occurred"`
	ExtraRelationKey   *string            `json:"extra.relation_key,omitempty" description:"Relation on which the exception occurred"`
	ExtraRelationIndex *int64             `json:"extra.relation_index,omitempty" description:"Relation index on which the exception occurred"`
	ExceptionClass     *string            `json:"exception.class" validate:"required" description:"Class name of the exception that occurred"`
	ExceptionMessage   *string            `json:"exception.message" validate:"required" description:"Message of the exception that occurred"`
	ExceptionBacktrace []string           `json:"exception.backtrace,omitempty" description:"Stack trace of the exception that occurred"`

	parsers.PantherLog
}

// ExtraServer has info about the server an exception occurred
type ExtraServer struct {
	OS      *ServerOS      `json:"os" validation:"required" description:"Server OS info"`
	Runtime *ServerRuntime `json:"runtime" validation:"required" description:"Runtime executing gitlab code"`
}

// ServerRuntime has info about the runtime where an exception occurred
type ServerRuntime struct {
	Name    *string `json:"name" validation:"required" description:"Runtime name"`
	Version *string `json:"version" validation:"required" description:"Runtime version"`
}

// ServerOS has info about the OS where an exception occurred
type ServerOS struct {
	Name    *string `json:"name" validation:"required" description:"OS name"`
	Version *string `json:"version" validation:"required" description:"OS version"`
	Build   *string `json:"build" validation:"required" description:"OS build"`
}

// ExceptionsParser parses gitlab rails logs
type ExceptionsParser struct{}

var _ parsers.LogParser = (*ExceptionsParser)(nil)

// New creates a new parser
func (p *ExceptionsParser) New() parsers.LogParser {
	return &ExceptionsParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ExceptionsParser) Parse(log string) ([]*parsers.PantherLog, error) {
	gitlabExceptions := Exceptions{}

	err := jsoniter.UnmarshalFromString(log, &gitlabExceptions)
	if err != nil {
		return nil, err
	}

	gitlabExceptions.updatePantherFields(p)

	if err := parsers.Validator.Struct(gitlabExceptions); err != nil {
		return nil, err
	}

	return gitlabExceptions.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *ExceptionsParser) LogType() string {
	return TypeExceptions
}

func (event *Exceptions) updatePantherFields(p *ExceptionsParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
}
