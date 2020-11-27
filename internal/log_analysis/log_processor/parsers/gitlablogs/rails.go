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

// Production is a a GitLab Production controller log line from a non-API endpoint
// nolint:lll
type Production struct {
	Method                pantherlog.String  `json:"method" validate:"required" description:"The HTTP method of the request"`
	Path                  pantherlog.String  `json:"path" validate:"required" description:"The URL path for the request"`
	Format                pantherlog.String  `json:"format" description:"The response output format"`
	Controller            pantherlog.String  `json:"controller" description:"The Production controller class name"`
	Action                pantherlog.String  `json:"action" description:"The Production controller action"`
	Status                pantherlog.Int64   `json:"status" validate:"required" description:"The HTTP response status code"`
	Time                  pantherlog.Time    `json:"time" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The request timestamp"`
	Params                []QueryParam       `json:"params" description:"The URL query parameters"`
	RemoteIP              pantherlog.String  `json:"remote_ip" panther:"ip" description:"The remote IP address of the HTTP request"`
	UserID                pantherlog.Int64   `json:"user_id" description:"The user id of the request"`
	UserName              pantherlog.String  `json:"username" panther:"username" description:"The username of the request"`
	UserAgent             pantherlog.String  `json:"ua" description:"The User-Agent of the requester"`
	QueueDurationSeconds  pantherlog.Float32 `json:"queue_duration_s" description:"Total time that the request was queued inside GitLab Workhorse"`
	GitalyCalls           pantherlog.Int64   `json:"gitaly_calls" description:"Total number of calls made to Gitaly"`
	GitalyDurationSeconds pantherlog.Float32 `json:"gitaly_duration_s" description:"Total time taken by Gitaly calls"`
	RedisCalls            pantherlog.Int64   `json:"redis_calls" description:"Total number of calls made to Redis"`
	RedisDurationSeconds  pantherlog.Float32 `json:"redis_duration_s" description:"Total time to retrieve data from Redis"`
	RedisReadBytes        pantherlog.Int64   `json:"redis_read_bytes" description:"Total bytes read from Redis"`
	RedisWriteBytes       pantherlog.Int64   `json:"redis_write_bytes" description:"Total bytes written to Redis"`
	CorrelationID         pantherlog.String  `json:"correlation_id" panther:"trace_id" description:"Request unique id across logs"`
	CPUSeconds            pantherlog.Float32 `json:"cpu_s" description:" Total time spent on CPU"`
	DBDurationSeconds     pantherlog.Float32 `json:"db_duration_s" description:"Total time to retrieve data from PostgreSQL"`
	ViewDurationSeconds   pantherlog.Float32 `json:"view_duration_s" description:" Total time taken inside the Rails views"`
	DurationSeconds       pantherlog.Float32 `json:"duration_s" validate:"required" description:"Total time taken to retrieve the request"`
	MetaCallerID          pantherlog.String  `json:"meta.caller_id" description:"Caller ID"`
	Location              pantherlog.String  `json:"location" description:"(Applies only to redirects) The redirect URL"`
	ExceptionClass        pantherlog.String  `json:"exception.class" description:"Class name of the exception that occurred"`
	ExceptionMessage      pantherlog.String  `json:"exception.message" description:"Message of the exception that occurred"`
	ExceptionBacktrace    []string           `json:"exception.backtrace" description:"Stack trace of the exception that occurred"`
	EtagRoute             pantherlog.String  `json:"etag_route" description:"Route name etag (on redirects)"`
}

// QueryParam is an HTTP query param as logged by LogRage
type QueryParam struct {
	Key   pantherlog.String     `json:"key" validate:"required" description:"Query parameter name"`
	Value pantherlog.RawMessage `json:"value" description:"Query parameter value"`
}
