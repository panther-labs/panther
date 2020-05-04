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
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type LogEntryAuditLog struct {
	LogEntry
	Payload AuditLog `json:"protoPayload" validate:"required" description:"The AuditLog payload"`

	parsers.PantherLog
}

const (
	TypeAuditLog = "GCP.AuditLog"

	// nolint:lll
	AuditLogDesc = `Cloud Audit Logs maintains three audit logs for each Google Cloud project, folder, and organization: Admin Activity, Data Access, and System Event.
Google Cloud services write audit log entries to these logs to help you answer the questions of "who did what, where, and when?" within your Google Cloud resources.

Reference: https://cloud.google.com/logging/docs/audit
`
	AuditLogActivityLogID = "cloudaudit.googleapis.com%2Factivity"
	AuditLogDataLogID     = "cloudaudit.googleapis.com%2Fdata_access"
	AuditLogSystemLogID   = "cloudaudit.googleapis.com%2Fsystem_event"
)

type AuditLogParser struct{}

var _ parsers.LogParser = (*AuditLogParser)(nil)

func NewAuditLogParser() parsers.LogParser {
	return &AuditLogParser{}
}

func (p *AuditLogParser) LogType() string {
	return TypeAuditLog
}

// New creates a new log parser instance
func (p *AuditLogParser) New() parsers.LogParser {
	return &AuditLogParser{}
}

// Parse implements parsers.LogParser interface
func (p *AuditLogParser) Parse(log string) ([]*parsers.PantherLog, error) {
	entry := LogEntryAuditLog{}
	if err := jsoniter.UnmarshalFromString(log, &entry); err != nil {
		return nil, err
	}
	switch id := entry.LogID(); id {
	case AuditLogActivityLogID, AuditLogDataLogID, AuditLogSystemLogID:
	default:
		return nil, errors.Errorf("invalid LogID %q != %s", id, []string{
			AuditLogActivityLogID,
			AuditLogDataLogID,
			AuditLogSystemLogID,
		})
	}
	ts := entry.Timestamp
	if ts == nil {
		// Fallback to ReceiveTimestamp which is a required field to get a timestamp hopefully closer to the actual event timestamp.
		ts = entry.ReceiveTimestamp
	}
	entry.SetCoreFields(TypeAuditLog, ts, &entry)
	if entry.HTTPRequest != nil {
		entry.AppendAnyIPAddressPtr(entry.HTTPRequest.RemoteIP)
		entry.AppendAnyIPAddressPtr(entry.HTTPRequest.ServerIP)
	}
	if meta := entry.Payload.RequestMetadata; meta != nil {
		entry.AppendAnyIPAddressPtr(meta.CallerIP)
	}
	if err := parsers.Validator.Struct(entry); err != nil {
		return nil, err
	}
	return entry.Logs(), nil
}

// nolint:lll
type AuditLog struct {
	PayloadType        *string             `json:"@type" validate:"required,eq=type.googleapis.com/google.cloud.audit.AuditLog" description:"The type of payload"`
	ServiceName        *string             `json:"serviceName,omitempty" description:"The name of the API service performing the operation"`
	MethodName         *string             `json:"methodName,omitempty" description:"The name of the service method or operation. For API calls, this should be the name of the API method."`
	ResourceName       *string             `json:"resourceName,omitempty" description:"The resource or collection that is the target of the operation. The name is a scheme-less URI, not including the API service name."`
	NumResponseItems   *numerics.Int64     `json:"numResponseItems,omitempty" description:"The number of items returned from a List or Query API method, if applicable."`
	Status             *Status             `json:"status,omitempty" description:" The status of the overall operation."`
	AuthenticationInfo *AuthenticationInfo `json:"authenticationInfo,omitempty" description:"Authentication information."`
	AuthorizationInfo  []AuthorizationInfo `json:"authorizationInfo,omitempty" validate:"omitempty,dive" description:"Authorization information. If there are multiple resources or permissions involved, then there is one AuthorizationInfo element for each {resource, permission} tuple."`
	RequestMetadata    *RequestMetadata    `json:"requestMetadata,omitempty" description:"Metadata about the request"`
	Request            jsoniter.RawMessage `json:"request,omitempty" description:"The operation request. This may not include all request parameters, such as those that are too large, privacy-sensitive, or duplicated elsewhere in the log record. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property."`
	Response           jsoniter.RawMessage `json:"response,omitempty" description:"The operation response. This may not include all response parameters, such as those that are too large, privacy-sensitive, or duplicated elsewhere in the log record. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property."`
	ServiceData        jsoniter.RawMessage `json:"serviceData,omitempty" description:"Other service-specific data about the request, response, and other activities."`
}

// nolint:lll
type Status struct {
	// https://cloud.google.com/vision/docs/reference/rpc/google.rpc#google.rpc.Code
	Code    *int32              `json:"code,omitempty" description:"The status code, which should be an enum value of google.rpc.Code."`
	Message *string             `json:"message,omitempty" description:"A developer-facing error message, which should be in English."`
	Details jsoniter.RawMessage `json:"details,omitempty" description:"A list of messages that carry the error details. There is a common set of message types for APIs to use."`
}

// nolint:lll
type AuthenticationInfo struct {
	PrincipalEmail    *string `json:"principalEmail" validate:"required" description:"The email address of the authenticated user making the request."`
	AuthoritySelector *string `json:"authoritySelector,omitempty" description:"The authority selector specified by the requestor, if any. It is not guaranteed that the principal was allowed to use this authority."`
}

// nolint:lll
type AuthorizationInfo struct {
	Resource   *string `json:"resource" validate:"required" description:"The resource being accessed, as a REST-style string."`
	Permission *string `json:"permission" validate:"required" description:"The required IAM permission"`
	Granted    *bool   `json:"granted" validate:"required" description:" Whether or not authorization for resource and permission was granted."`
}

// nolint:lll
// Reference https://cloud.google.com/service-infrastructure/docs/service-control/reference/rest/v1/AuditLog#RequestMetadata
type RequestMetadata struct {
	CallerIP                *string             `json:"callerIP,omitempty"  description:"The IP address of the caller."`
	CallerSuppliedUserAgent *string             `json:"callerSuppliedUserAgent,omitempty"  description:"The user agent of the caller. This information is not authenticated and should be treated accordingly."`
	CallerNetwork           *string             `json:"callerNetwork,omitempty" description:"The network of the caller. Set only if the network host project is part of the same GCP organization (or project) as the accessed resource."`
	RequestAttributes       jsoniter.RawMessage `json:"requestAttributes,omitempty" description:"Request attributes used in IAM condition evaluation. This field contains request attributes like request time and access levels associated with the request."`
	DestinationAttributes   jsoniter.RawMessage `json:"destinationAttributes,omitempty" description:"The destination of a network activity, such as accepting a TCP connection."`
}

// IAM Data audit log
// nolint:lll
type AuditData struct {
	PermissionDelta PermissionDelta `json:"permissionDelta" validate:"required" description:" The permissionDelta when when creating or updating a Role."`
}

// nolint:lll
type PermissionDelta struct {
	AddedPermissions   []string `json:"addedPermissions,omitempty" description:"Added permissions"`
	RemovedPermissions []string `json:"removedPermissions,omitempty" description:"Removed permissions"`
}

// The following structs seem to be deprecated but still used by some services inside `RequestMetadata`
// After discussion we decided to map the to RawMessage blobs but keep them here for future use in other GCPLogs

// nolint
type v1RequestAttributes struct {
	ID       *string            `json:"id,omitempty" description:"The unique ID for a request, which can be propagated to downstream systems."`
	Method   *string            `json:"method,omitempty" description:"The HTTP request method, such as GET, POST."`
	Headers  map[string]string  `json:"headers,omitempty" description:"The HTTP request headers. If multiple headers share the same key, they must be merged according to the HTTP spec. All header keys must be lowercased, because HTTP header keys are case-insensitive"`
	Path     *string            `json:"path,omitempty" description:"The HTTP URL path."`
	Host     *string            `json:"host,omitempty" description:"The HTTP request host header value."`
	Scheme   *string            `json:"scheme,omitempty" description:"The HTTP URL scheme, such as http and https."`
	Query    *string            `json:"query,omitempty" description:"The HTTP URL query in the format of 'name1=value&name2=value2', as it appears in the first line of the HTTP request. No decoding is performed."`
	Fragment *string            `json:"fragment,omitempty" description:"The HTTP URL fragment. No URL decoding is performed."`
	Time     *timestamp.RFC3339 `json:"time,omitempty" description:"The timestamp when the destination service receives the first byte of the request."`
	Size     *int64             `json:"size,omitempty" description:"The HTTP request size in bytes. If unknown, it must be -1."`
	Protocol *string            `json:"protocol,omitempty" description:"The network protocol used with the request, such as 'http/1.1', 'spdy/3', 'h2', 'h2c', 'webrtc', 'tcp', 'udp', 'quic'."`
	Reason   *string            `json:"reason,omitempty" description:"A special parameter for request reason. It is used by security systems to associate auditing information with a request."`
	Auth     *v1Auth            `json:"auth,omitempty" description:"A special parameter for request reason. It is used by security systems to associate auditing information with a request."`
}

// nolint
type v1Peer struct {
	IP         *string           `json:"ip,omitempty" description:"The IP address of the peer."`
	Port       *numerics.Integer `json:"port,omitempty" description:"The network port of the peer."`
	Service    *string           `json:"service,omitempty" description:"The canonical service name of the peer."`
	Labels     Labels            `json:"labels,omitempty" description:"The labels associated with the peer."`
	Principal  *string           `json:"principal,omitempty" description:"The identity of this peer. Similar to Request.auth.principal, but relative to the peer instead of the request."`
	RegionCode *string           `json:"regionCode,omitempty" description:"The CLDR country/region code associated with the above IP address. If the IP address is private, the regionCode should reflect the physical location where this peer is running."`
}

// nolint
type v1Auth struct {
	Principal    *string              `json:"principal,omitempty" description:"The authenticated principal. Reflects the issuer (iss) and subject (sub) claims within a JWT."`
	Audiences    []string             `json:"audiences,omitempty" description:"The intended audience(s) for this authentication information. Reflects the audience (aud) claim within a JWT."`
	Presenter    *string              `json:"presenter,omitempty" description:"The authorized presenter of the credential. Reflects the optional Authorized Presenter (azp) claim within a JWT or the OAuth client id."`
	AccessLevels []string             `json:"accessLevels,omitempty" description:"A list of access level resource names that allow resources to be accessed by authenticated requester. It is part of Secure GCP processing for the incoming request."`
	Claims       *jsoniter.RawMessage `json:"claims,omitempty" description:"Structured claims presented with the credential. JWTs include {key: value} pairs for standard and private claims."`
}
