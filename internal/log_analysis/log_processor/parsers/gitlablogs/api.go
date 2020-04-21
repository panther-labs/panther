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

// TypeAPI is the type of the GitLabAPI log record
const TypeAPI = PantherPrefix + ".API"

// APIDesc describes the GitLabAPI log record
var APIDesc = `GitLab log for API requests received from GitLab
Reference: https://docs.gitlab.com/ee/administration/logs.html#api_jsonlog`

// API is a a GitLab log line from an internal API endpoint
// TODO: Check more samples from [Lograge](https://github.com/roidrage/lograge/) JSON output to find missing fields
// nolint: lll
type API struct {
	Time           *timestamp.RFC3339 `json:"time" validate:"required" description:"The request timestamp"`
	Severity       *string            `json:"severity" validate:"required" description:"The log level"`
	Duration       *float32           `json:"duration" validate:"required" description:"The time spent serving the request (in milliseconds)"`
	DB             *float32           `json:"db,omitempty" description:"The time spent quering the database (in milliseconds)"`
	View           *float32           `json:"view,omitempty" description:"The time spent rendering the view for the Rails controller (in milliseconds)"`
	Status         *int               `json:"status" validate:"required" description:"The HTTP response status code"`
	Method         *string            `json:"method" validate:"required" description:"The HTTP method of the request"`
	Path           *string            `json:"path" validate:"required" description:"The URL path for the request"`
	Params         []QueryParam       `json:"params,omitempty" description:"The URL query parameters"`
	Host           *string            `json:"host" validate:"required" description:"Hostname serving the request"`
	UserAgent      *string            `json:"ua,omitempty" description:"User-Agent HTTP header"`
	Route          *string            `json:"route" validate:"required" description:"Rails route for the API endpoint"`
	RemoteIP       *string            `json:"remote_ip,omitempty" description:"The remote IP address of the HTTP request"`
	UserID         *int64             `json:"user_id,omitempty" description:"The user id of the request"`
	UserName       *string            `json:"username,omitempty" description:"The username of the request"`
	GitalyCalls    *int               `json:"gitaly_calls,omitempty" description:"Total number of calls made to Gitaly"`
	GitalyDuration *float32           `json:"gitaly_duration,omitempty" description:"Total time taken by Gitaly calls"`
	QueueDuration  *float32           `json:"queue_duration,omitempty" description:"Total time that the request was queued inside GitLab Workhorse"`
	// TODO: Check if API logs behave the same as Rails logs when an exception occurs
	// CorrelationID      *string      `json:"correlation_id,omitempty" description:"Request unique id across logs"`
	// CPUSeconds         *float64     `json:"cpu_s,omitempty" description:"CPU seconds"` // TODO: Check what this field information is about
	// ExceptionClass     *string      `json:"exception.class,omitempty" description:"Class name of the exception that occurred"`
	// ExceptionMessage   *string      `json:"exception.message,omitempty" description:"Message of the exception that occurred"`
	// ExceptionBacktrace []*string    `json:"exception.backtrace,omitempty" description:"Stack trace of the exception that occurred"`

	parsers.PantherLog
}

// APIParser parses gitlab rails logs
type APIParser struct{}

var _ parsers.LogParser = (*APIParser)(nil)

// New creates a new parser
func (p *APIParser) New() parsers.LogParser {
	return &APIParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *APIParser) Parse(log string) ([]*parsers.PantherLog, error) {
	gitlabAPI := API{}

	err := jsoniter.UnmarshalFromString(log, &gitlabAPI)
	if err != nil {
		return nil, err
	}

	gitlabAPI.updatePantherFields(p)

	if err := parsers.Validator.Struct(gitlabAPI); err != nil {
		return nil, err
	}

	return gitlabAPI.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *APIParser) LogType() string {
	return TypeAPI
}

func (event *API) updatePantherFields(p *APIParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
	event.AppendAnyIPAddressPtr(event.RemoteIP)
}
