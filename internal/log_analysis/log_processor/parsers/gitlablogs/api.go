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

// API is a a GitLab log line from an internal API endpoint
// nolint: lll
type API struct {
	Time                  pantherlog.Time    `json:"time" event_time:"true" tcodec:"rfc3339" validate:"required" description:"The request timestamp"`
	Severity              pantherlog.String  `json:"severity" validate:"required" description:"The log level"`
	DurationSeconds       pantherlog.Float32 `json:"duration_s" validate:"required" description:"The time spent serving the request (in seconds)"`
	DBDurationSeconds     pantherlog.Float32 `json:"db_duration_s" description:"The time spent quering the database (in seconds)"`
	ViewDurationSeconds   pantherlog.Float32 `json:"view_duration_s" description:"The time spent rendering the view for the Rails controller (in seconds)"`
	Status                pantherlog.Int16   `json:"status" validate:"required" description:"The HTTP response status code"`
	Method                pantherlog.String  `json:"method" validate:"required" description:"The HTTP method of the request"`
	Path                  pantherlog.String  `json:"path" validate:"required" description:"The URL path for the request"`
	Params                []QueryParam       `json:"params" description:"The URL query parameters"`
	Host                  pantherlog.String  `json:"host" panther:"hostname" validate:"required" description:"Hostname serving the request"`
	UserAgent             pantherlog.String  `json:"ua" description:"User-Agent HTTP header"`
	Route                 pantherlog.String  `json:"route" validate:"required" description:"Rails route for the API endpoint"`
	RemoteIP              pantherlog.String  `json:"remote_ip" panther:"ip" description:"The remote IP address of the HTTP request"`
	UserID                pantherlog.Int64   `json:"user_id" description:"The user id of the request"`
	UserName              pantherlog.String  `json:"username" panther:"username" description:"The username of the request"`
	GitalyCalls           pantherlog.Int64   `json:"gitaly_calls" description:"Total number of calls made to Gitaly"`
	GitalyDurationSeconds pantherlog.Float32 `json:"gitaly_duration_s" description:"Total time taken by Gitaly calls"`
	RedisCalls            pantherlog.Int64   `json:"redis_calls" description:"Total number of calls made to Redis"`
	RedisDurationSeconds  pantherlog.Float32 `json:"redis_duration_s" description:"Total time to retrieve data from Redis"`
	CorrelationID         pantherlog.String  `json:"correlation_id" panther:"trace_id" description:"Request unique id across logs"`
	QueueDuration         pantherlog.Float32 `json:"queue_duration_s" description:"Total time that the request was queued inside GitLab Workhorse"`
	MetaUser              pantherlog.String  `json:"meta.user" panther:"username" description:"User that invoked the request"`
	MetaProject           pantherlog.String  `json:"meta.project" description:"Project associated with the request"`
	MetaRootNamespace     pantherlog.String  `json:"meta.root_namespace" description:"Root namespace"`
	MetaCallerID          pantherlog.String  `json:"meta.caller_id" description:"Caller ID"`
	// TODO: Check if API logs behave the same as Production logs when an exception occurs
	// ExceptionClass     *string      `json:"exception.class,omitempty" description:"Class name of the exception that occurred"`
	// ExceptionMessage   *string      `json:"exception.message,omitempty" description:"Message of the exception that occurred"`
	// ExceptionBacktrace []*string    `json:"exception.backtrace,omitempty" description:"Stack trace of the exception that occurred"`
}
