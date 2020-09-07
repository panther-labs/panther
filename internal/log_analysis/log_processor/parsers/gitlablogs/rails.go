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

// Production is a a GitLab Production controller log line from a non-API endpoint
// nolint:lll
type Production struct {
	Method                *string            `json:"method" validate:"required" description:"The HTTP method of the request"`
	Path                  *string            `json:"path" validate:"required" description:"The URL path for the request"`
	Format                *string            `json:"format" description:"The response output format"`
	Controller            *string            `json:"controller,omitempty" description:"The Production controller class name"`
	Action                *string            `json:"action,omitempty" validate:"required_without=EtagRoute" description:"The Production controller action"`
	Status                *int               `json:"status" validate:"required" description:"The HTTP response status code"`
	Time                  *timestamp.RFC3339 `json:"time" validate:"required" description:"The request timestamp"`
	Params                []QueryParam       `json:"params,omitempty" description:"The URL query parameters"`
	RemoteIP              *string            `json:"remote_ip,omitempty" description:"The remote IP address of the HTTP request"`
	UserID                *int64             `json:"user_id,omitempty" description:"The user id of the request"`
	UserName              *string            `json:"username,omitempty" description:"The username of the request"`
	UserAgent             *string            `json:"ua,omitempty" description:"The User-Agent of the requester"`
	QueueDurationSeconds  *float32           `json:"queue_duration_s,omitempty" description:"Total time that the request was queued inside GitLab Workhorse"`
	GitalyCalls           *int               `json:"gitaly_calls,omitempty" description:"Total number of calls made to Gitaly"`
	GitalyDurationSeconds *float32           `json:"gitaly_duration_s,omitempty" description:"Total time taken by Gitaly calls"`
	RedisCalls            *int               `json:"redis_calls,omitempty" description:"Total number of calls made to Redis"`
	RedisDurationSeconds  *float32           `json:"redis_duration_s,omitempty" description:"Total time to retrieve data from Redis"`
	RedisReadBytes        *int64             `json:"redis_read_bytes,omitempty" description:"Total bytes read from Redis"`
	RedisWriteBytes       *int64             `json:"redis_write_bytes,omitempty" description:"Total bytes written to Redis"`
	CorrelationID         *string            `json:"correlation_id,omitempty" description:"Request unique id across logs"`
	CPUSeconds            *float32           `json:"cpu_s,omitempty" description:" Total time spent on CPU"`
	DBDurationSeconds     *float32           `json:"db_duration_s,omitempty" description:"Total time to retrieve data from PostgreSQL"`
	ViewDurationSeconds   *float32           `json:"view_duration_s,omitempty" description:" Total time taken inside the Rails views"`
	DurationSeconds       *float32           `json:"duration_s" validate:"required" description:"Total time taken to retrieve the request"`
	MetaCallerID          *string            `json:"meta.caller_id,omitempty" description:"Caller ID"`
	Location              *string            `json:"location" description:"(Applies only to redirects) The redirect URL"`
	ExceptionClass        *string            `json:"exception.class,omitempty" description:"Class name of the exception that occurred"`
	ExceptionMessage      *string            `json:"exception.message,omitempty" description:"Message of the exception that occurred"`
	ExceptionBacktrace    []string           `json:"exception.backtrace,omitempty" description:"Stack trace of the exception that occurred"`
	EtagRoute             *string            `json:"etag_route,omitempty" validate:"required_without=Action" description:"Route name etag (on redirects)"`

	parsers.PantherLog
}

// QueryParam is an HTTP query param as logged by LogRage
type QueryParam struct {
	Key   *string             `json:"key" validate:"required" description:"Query parameter name"`
	Value jsoniter.RawMessage `json:"value,omitempty" description:"Query parameter value"`
}

// ProductionParser parses gitlab rails logs
type ProductionParser struct{}

var _ parsers.LogParser = (*ProductionParser)(nil)

// New creates a new parser
func (p *ProductionParser) New() parsers.LogParser {
	return &ProductionParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ProductionParser) Parse(log string) ([]*parsers.PantherLog, error) {
	gitlabRails := Production{}

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
func (p *ProductionParser) LogType() string {
	return TypeProduction
}

func (event *Production) updatePantherFields(p *ProductionParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
	event.AppendAnyIPAddressPtr(event.RemoteIP)
}
