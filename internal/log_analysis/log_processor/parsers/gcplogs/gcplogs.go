package gcplogs

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// Package gcplogs has log parsers for Google Cloud Platform

// nolint:lll
type LogEntry struct {
	LogName          *string                 `json:"logName" validate:"required" description:"The resource name of the log to which this log entry belongs."`
	Severity         LogSeverity             `json:"severity,omitempty" description:"The severity of the log entry. The default value is LogSeverity.DEFAULT."`
	InsertID         *string                 `json:"insertId,omitempty" description:"A unique identifier for the log entry."`
	Resource         MonitoredResource       `json:"resource" validate:"required" description:"The monitored resource that produced this log entry."`
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

type LogSeverity int

const (
	SeverityDefault   LogSeverity = 0
	SeverityDebug     LogSeverity = 100
	SeverityInfo      LogSeverity = 200
	SeverityNotice    LogSeverity = 300
	SeverityWarning   LogSeverity = 400
	SeverityError     LogSeverity = 500
	SeverityCritical  LogSeverity = 600
	SeverityAlert     LogSeverity = 700
	SeverityEmergency LogSeverity = 800
)

// nolint:lll
type HTTPRequest struct {
	RequestMethod *string         `json:"requestMethod" validate:"required" description:"The request HTTP method."`
	RequestURL    *string         `json:"requestURL" validate:"required" description:"The scheme (http, https), the host name, the path and the query portion of the URL that was requested."`
	RequestSize   *numerics.Int64 `json:"requestSize" validate:"required" description:"The size of the HTTP request message in bytes, including the request headers and the request body."`
	Status        *int16          `json:"status" validate:"required" description:"The response HTTP status code"`
	ResponseSize  *numerics.Int64 `json:"responseSize" validate:"required" description:"The size of the HTTP response message sent back to the client, in bytes, including the response headers and the response body."`
	UserAgent     *string         `json:"userAgent" validate:"required" description:"The user agent sent by the client."`
	RemoteIP      *string         `json:"remoteIP" validate:"required" description:"The IP address (IPv4 or IPv6) of the client that issued the HTTP request."`
	ServerIP      *string         `json:"serverIP" validate:"required" description:"The IP address (IPv4 or IPv6) of the origin server that the request was sent to."`
	Referer       *string         `json:"referer" validate:"required" description:"The referer URL of the request"`
	// FIXME Parse duration?
	Latency        *string         `json:"latency" validate:"required" description:"The request processing latency in seconds on the server, from the time the request was received until the response was sent."`
	CacheLookup    *bool           `json:"cacheLookup,omitempty"  description:"Whether or not a cache lookup was attempted."`
	CacheHit       *bool           `json:"cacheHit,omitempty"  description:"Whether or not an entity was served from cache (with or without validation)."`
	CacheValidated *bool           `json:"cacheValidatedWithOriginServer,omitempty" description:"Whether or not an entity was served from cache (with or without validation)."`
	CacheFillBytes *numerics.Int64 `json:"cacheFillBytes,omitempty" description:"Whether or not an entity was served from cache (with or without validation)."`
	Protocol       *string         `json:"protocol" validate:"required" description:"Protocol used for the request."`
}

// nolint:lll
type LogEntrySourceLocation struct {
	File     *string         `json:"file,omitempty" description:"Source file name. Depending on the runtime environment, this might be a simple name or a fully-qualified name."`
	Line     *numerics.Int64 `json:"line" description:"Line within the source file. 1-based; 0 indicates no line number available."`
	Function *string         `json:"function,omitempty" description:"Human-readable name of the function or method being invoked, with optional context such as the class or package name."`
}
