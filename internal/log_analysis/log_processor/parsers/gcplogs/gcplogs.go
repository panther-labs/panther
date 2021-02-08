// Package gcplogs has log parsers for Google Cloud Platform
package gcplogs

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
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const (
	LogTypePrefix = "GCP"
	TypeAuditLog  = LogTypePrefix + ".AuditLog"
)

// LogTypes exports the available log type entries
func LogTypes() logtypes.Group {
	return logTypes
}

//nolint: lll
var logTypes = logtypes.Must(LogTypePrefix, logtypes.Config{
	Name: TypeAuditLog,
	Description: `Cloud Audit Logs maintains three audit logs for each Google Cloud project, folder, and organization: Admin Activity, Data Access, and System Event.
Google Cloud services write audit log entries to these logs to help you answer the questions of "who did what, where, and when?" within your Google Cloud resources.
`,
	ReferenceURL: `https://cloud.google.com/logging/docs/audit`,
	Schema:       LogEntryAuditLog{},
	NewParser:    parsers.AdapterFactory(&AuditLogParser{}),
})

// nolint:lll
type LogEntry struct {
	LogName          *string                 `json:"logName" validate:"required" description:"The resource name of the log to which this log entry belongs."`
	Severity         *string                 `json:"severity,omitempty" description:"The severity of the log entry. The default value is LogSeverity.DEFAULT."`
	InsertID         *string                 `json:"insertId,omitempty" description:"A unique identifier for the log entry."`
	Resource         *MonitoredResource      `json:"resource,omitempty" description:"The monitored resource that produced this log entry."`
	Timestamp        *timestamp.RFC3339      `json:"timestamp,omitempty" description:"The time the event described by the log entry occurred."`
	ReceiveTimestamp *timestamp.RFC3339      `json:"receiveTimestamp" validate:"required" description:"The time the log entry was received by Logging."`
	Labels           Labels                  `json:"labels,omitempty" description:"A set of user-defined (key, value) data that provides additional information about the log entry."`
	Operation        *LogEntryOperation      `json:"operation,omitempty" description:"Information about an operation associated with the log entry, if applicable."`
	Trace            *string                 `json:"trace,omitempty" description:"Resource name of the trace associated with the log entry, if any."`
	HTTPRequest      *HTTPRequest            `json:"httpRequest,omitempty" description:"Information about the HTTP request associated with this log entry, if applicable."`
	SpanID           *string                 `json:"spanId,omitempty" description:"The span ID within the trace associated with the log entry."`
	TraceSampled     *bool                   `json:"traceSampled,omitempty" description:"The sampling decision of the trace associated with the log entry."`
	SourceLocation   *LogEntrySourceLocation `json:"sourceLocation,omitempty" description:"Source code location information associated with the log entry, if any."`
}

// LogID extracts the log ID from a `LogName` field.
// GCP logs are aggregated and use log id to differentiate different log types.
// A log ID is URL encoded is always the trailing path segment of a LogName.
func (entry *LogEntry) LogID() string {
	if entry == nil {
		return ""
	}
	if entry.LogName == nil {
		return ""
	}
	name := *entry.LogName
	// Find the last path segment in a LogName
	if pos := strings.LastIndexByte(name, '/'); 0 <= pos && pos < len(name) {
		return name[pos+1:]
	}
	return ""
}

// nolint:lll
type MonitoredResource struct {
	Type   *string `json:"type" validate:"required" description:"Type of resource that produced this log entry"`
	Labels Labels  `json:"labels" validate:"required" description:"Labels describing the resource"`
}

type Labels map[string]string

// nolint:lll
type LogEntryOperation struct {
	ID       *string `json:"id,omitempty" description:"Whether or not an entity was served from cache (with or without validation)."`
	Producer *string `json:"producer,omitempty" description:"An arbitrary producer identifier. The combination of id and producer must be globally unique."`
	First    *bool   `json:"first,omitempty" description:"This is the first entry in an operation"`
	Last     *bool   `json:"last,omitempty" description:"This is the last entry in an operation"`
}

// nolint:lll
type HTTPRequest struct {
	RequestMethod  *string         `json:"requestMethod,omitempty" description:"The request HTTP method."`
	RequestURL     *string         `json:"requestURL,omitempty" description:"The scheme (http, https), the host name, the path and the query portion of the URL that was requested."`
	RequestSize    *numerics.Int64 `json:"requestSize,omitempty" description:"The size of the HTTP request message in bytes, including the request headers and the request body."`
	Status         *int16          `json:"status,omitempty" description:"The response HTTP status code"`
	ResponseSize   *numerics.Int64 `json:"responseSize,omitempty" description:"The size of the HTTP response message sent back to the client, in bytes, including the response headers and the response body."`
	UserAgent      *string         `json:"userAgent,omitempty"  description:"The user agent sent by the client."`
	RemoteIP       *string         `json:"remoteIP,omitempty"  description:"The IP address (IPv4 or IPv6) of the client that issued the HTTP request."`
	ServerIP       *string         `json:"serverIP,omitempty"  description:"The IP address (IPv4 or IPv6) of the origin server that the request was sent to."`
	Referer        *string         `json:"referer,omitempty" description:"The referer URL of the request"`
	Latency        *string         `json:"latency,omitempty" description:"The request processing latency in seconds on the server, from the time the request was received until the response was sent."`
	CacheLookup    *bool           `json:"cacheLookup,omitempty"  description:"Whether or not a cache lookup was attempted."`
	CacheHit       *bool           `json:"cacheHit,omitempty"  description:"Whether or not an entity was served from cache (with or without validation)."`
	CacheValidated *bool           `json:"cacheValidatedWithOriginServer,omitempty" description:"Whether or not an entity was served from cache (with or without validation)."`
	CacheFillBytes *numerics.Int64 `json:"cacheFillBytes,omitempty" description:"Whether or not an entity was served from cache (with or without validation)."`
	Protocol       *string         `json:"protocol,omitempty" description:"Protocol used for the request."`
}

// nolint:lll
type LogEntrySourceLocation struct {
	File     *string         `json:"file,omitempty" description:"Source file name. Depending on the runtime environment, this might be a simple name or a fully-qualified name."`
	Line     *numerics.Int64 `json:"line" description:"Line within the source file. 1-based; 0 indicates no line number available."`
	Function *string         `json:"function,omitempty" description:"Human-readable name of the function or method being invoked, with optional context such as the class or package name."`
}
