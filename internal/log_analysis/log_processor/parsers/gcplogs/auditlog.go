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
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
)

type LogEntryAuditLog struct {
	LogEntry
	Payload AuditLog `json:"protoPayload" validate:"required" description:"The AuditLog payload"`

	parsers.PantherLog
}

const TypeAuditLogActivity = "GCP.AuditLogActivity"
const TypeAuditLogData = "GCP.AuditLogDataAccess"
const TypeAuditLogSystem = "GCP.AuditLogSystemEvent"

// nolint:lll
const AuditLogActivityDesc = `Admin Activity audit logs contain log entries for API calls or other administrative actions that modify the configuration or metadata of resources.
Reference: https://cloud.google.com/logging/docs/audit#admin-activity
`

// nolint:lll
const AuditLogSystemDesc = `System Event audit logs contain log entries for Google Cloud administrative actions that modify the configuration of resources.
Reference: https://cloud.google.com/logging/docs/audit#system-event
`

// nolint:lll
const AuditLogDataDesc = `Data Access audit logs contain API calls that read the configuration or metadata of resources, as well as user-driven API calls that create, modify, or read user-provided resource data.
Reference: https://cloud.google.com/logging/docs/audit#data-access
`

type AuditLogActivityParser struct{}
type AuditLogSystemParser struct{}
type AuditLogDataParser struct{}

const AuditLogActivityLogID = "cloudaudit.googleapis.com%2Factivity"
const AuditLogDataLogID = "cloudaudit.googleapis.com%2Fdata_access"
const AuditLogSystemLogID = "cloudaudit.googleapis.com%2Fsystem_event"

var _ parsers.LogParser = (*auditLogParser)(nil)

func NewAuditLogActivityParser() parsers.LogParser {
	return &auditLogParser{
		Type:  TypeAuditLogActivity,
		LogID: AuditLogActivityLogID,
	}
}
func NewAuditLogSystemParser() parsers.LogParser {
	return &auditLogParser{
		Type:  TypeAuditLogSystem,
		LogID: AuditLogSystemLogID,
	}
}
func NewAuditLogDataParser() parsers.LogParser {
	return &auditLogParser{
		Type:  TypeAuditLogData,
		LogID: AuditLogDataLogID,
	}
}

// LogType implements parsers.LogParser interface
func (p *auditLogParser) LogType() string {
	return p.Type
}

// New creates a new log parser instance
func (p *auditLogParser) New() parsers.LogParser {
	pp := *p
	return &pp
}

type auditLogParser struct {
	LogID string
	Type  string
}

// Parse implements parsers.LogParser interface
func (p *auditLogParser) Parse(log string) ([]*parsers.PantherLog, error) {
	entry := LogEntryAuditLog{}
	if err := jsoniter.UnmarshalFromString(log, &entry); err != nil {
		return nil, err
	}
	if id := entry.LogID(); id != p.LogID {
		return nil, fmt.Errorf("invalid LogID %q != %q", id, p.LogID)
	}
	ts := entry.Timestamp
	if ts == nil || ((*time.Time)(ts)).IsZero() {
		ts = entry.ReceiveTimestamp
	}
	entry.SetCoreFields(p.Type, ts, &entry)
	if entry.HTTPRequest != nil {
		entry.AppendAnyIPAddressPtr(entry.HTTPRequest.RemoteIP)
	}
	if meta := entry.Payload.RequestMetadata; meta != nil {
		entry.AppendAnyIPAddressPtr(entry.Payload.RequestMetadata.CallerIP)
	}
	if err := parsers.Validator.Struct(entry); err != nil {
		return nil, err
	}
	return entry.Logs(), nil
}

// nolint:lll
type AuditLog struct {
	PayloadType        *string             `json:"@type" validate:"required,eq=type.googleapis.com/google.cloud.audit.AuditLog" description:"The type of payload"`
	ServiceName        *string             `json:"serviceName" validate:"required" description:"The name of the API service performing the operation"`
	MethodName         *string             `json:"methodName" validate:"required" description:"The name of the service method or operation. For API calls, this should be the name of the API method."`
	ResourceName       *string             `json:"resourceName" validate:"required" description:"The resource or collection that is the target of the operation. The name is a scheme-less URI, not including the API service name."`
	NumResponseItems   *numerics.Int64     `json:"numResponseItems,omitempty" description:"The number of items returned from a List or Query API method, if applicable."`
	Status             *Status             `json:"status,omitempty" description:" The status of the overall operation."`
	AuthenticationInfo *AuthenticationInfo `json:"authenticationInfo,omitempty" description:"Authentication information."`
	AuthorizationInfo  []AuthorizationInfo `json:"authorizationInfo,omitempty" description:"Authorization information. If there are multiple resources or permissions involved, then there is one AuthorizationInfo element for each {resource, permission} tuple."`
	RequestMetadata    *RequestMetadata    `json:"requestMetadata,omitempty" description:"Metadata about the request"`
	Request            jsoniter.RawMessage `json:"request,omitempty" description:"The operation request. This may not include all request parameters, such as those that are too large, privacy-sensitive, or duplicated elsewhere in the log record. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property."`
	Response           jsoniter.RawMessage `json:"response,omitempty" description:"The operation response. This may not include all response parameters, such as those that are too large, privacy-sensitive, or duplicated elsewhere in the log record. When the JSON object represented here has a proto equivalent, the proto name will be indicated in the @type property."`
	ServiceData        jsoniter.RawMessage `json:"serviceData,omitempty" description:"Other service-specific data about the request, response, and other activities."`
}

// nolint:lll
type Status struct {
	// https://cloud.google.com/vision/docs/reference/rpc/google.rpc#google.rpc.Code
	Code    *int32              `json:"code" validate:"required" description:"The status code, which should be an enum value of google.rpc.Code."`
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
type RequestMetadata struct {
	CallerIP                *string `json:"callerIP" validate:"required" description:"The IP address of the caller."`
	CallerSuppliedUserAgent *string `json:"callerSuppliedUserAgent" validate:"required" description:"The user agent of the caller. This information is not authenticated and should be treated accordingly."`
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
