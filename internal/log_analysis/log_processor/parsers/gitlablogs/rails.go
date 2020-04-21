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

// TypeRails is the type of the GitLabRails log record
const TypeRails = PantherPrefix + ".Rails"

// RailsDesc describes the GitLabRails log record
var RailsDesc = `GitLab log for Rails controller requests received from GitLab
Reference: https://docs.gitlab.com/ee/administration/logs.html#production_jsonlog`

// Rails is a a GitLab Rails controller log line from a non-API endpoint
// TODO: Check more samples from [Lograge](https://github.com/roidrage/lograge/) JSON output to find missing fields
// nolint:lll
type Rails struct {
	Method             *string            `json:"method" validate:"required" description:"The HTTP method of the request"`
	Path               *string            `json:"path" validate:"required" description:"The URL path for the request"`
	Format             *string            `json:"format" validate:"required" description:"The response output format"`
	Controller         *string            `json:"controller" validate:"required" description:"The Rails controller class name"`
	Action             *string            `json:"action" validate:"required" description:"The Rails controller action"`
	Status             *int               `json:"status" validate:"required" description:"The HTTP response status code"`
	Duration           *float32           `json:"duration" validate:"required" description:"The time spent serving the request (in milliseconds)"`
	View               *float32           `json:"view,omitempty" description:"The time spent rendering the view for the Rails controller (in milliseconds)"`
	DB                 *float32           `json:"db,omitempty" description:"The time spent quering the database (in milliseconds)"`
	Time               *timestamp.RFC3339 `json:"time" validate:"required" description:"The request timestamp"`
	Params             []QueryParam       `json:"params,omitempty" description:"The URL query parameters"`
	RemoteIP           *string            `json:"remote_ip,omitempty" description:"The remote IP address of the HTTP request"`
	UserID             *int64             `json:"user_id,omitempty" description:"The user id of the request"`
	UserName           *string            `json:"username,omitempty" description:"The username of the request"`
	GitalyCalls        *int               `json:"gitaly_calls,omitempty" description:"Total number of calls made to Gitaly"`
	GitalyDuration     *float32           `json:"gitaly_duration,omitempty" description:"Total time taken by Gitaly calls"`
	QueueDuration      *float32           `json:"queue_duration,omitempty" description:"Total time that the request was queued inside GitLab Workhorse"`
	CorrelationID      *string            `json:"correlation_id,omitempty" description:"Request unique id across logs"`
	UserAgent          *string            `json:"ua,omitempty" description:"User-Agent HTTP header"`
	CPUSeconds         *float32           `json:"cpu_s,omitempty" description:"CPU seconds"` // TODO: Check what this field information is about
	ExceptionClass     *string            `json:"exception.class,omitempty" description:"Class name of the exception that occurred"`
	ExceptionMessage   *string            `json:"exception.message,omitempty" description:"Message of the exception that occurred"`
	ExceptionBacktrace []string           `json:"exception.backtrace,omitempty" description:"Stack trace of the exception that occurred"`

	parsers.PantherLog
}

// QueryParam is an HTTP query param as logged by LogRage
type QueryParam struct {
	Key   *string `json:"key" validate:"required" description:"Query parameter name"`
	Value *string `json:"value,omitempty" description:"Query parameter value"`
}

// RailsParser parses gitlab rails logs
type RailsParser struct{}

var _ parsers.LogParser = (*RailsParser)(nil)

// New creates a new parser
func (p *RailsParser) New() parsers.LogParser {
	return &RailsParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RailsParser) Parse(log string) ([]*parsers.PantherLog, error) {
	gitlabRails := Rails{}

	err := jsoniter.UnmarshalFromString(log, &gitlabRails)
	if err != nil {
		return nil, err
	}

	gitlabRails.updatePantherFields(p)

	if err := parsers.Validator.Struct(gitlabRails); err != nil {
		return nil, err
	}

	return gitlabRails.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *RailsParser) LogType() string {
	return TypeRails
}

func (event *Rails) updatePantherFields(p *RailsParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
	event.AppendAnyIPAddressPtr(event.RemoteIP)
}
