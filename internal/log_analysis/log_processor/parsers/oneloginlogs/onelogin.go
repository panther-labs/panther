package oneloginlogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeOneLogin = "OneLogin.Events"

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("OneLogin", logtypes.Config{
	Name: TypeOneLogin,
	Description: `OneLogin provides single sign-on and identity management for organizations
Panther Enterprise Only
`,
	ReferenceURL: `https://developers.onelogin.com/api-docs/1/events/event-resource`,
	Schema:       OneLogin{},
	NewParser:    parsers.AdapterFactory(&OneLoginParser{}),
})

// nolint:lll
type OneLogin struct {
	UUID                            *string                      `json:"uuid" validate:"required,uuid" description:"The Universal Unique Identifier for this message generated by OneLogin."`
	AccountID                       *int                         `json:"account_id" validate:"required" description:"Account that triggered the event."`
	EventTimestamp                  *timestamp.OneLoginTimestamp `json:"event_timestamp" validate:"required" description:"Time and date at which the event was created. This value is autogenerated by OneLogin."`
	ErrorDescription                *string                      `json:"error_description,omitempty" description:"Provisioning error details, if applicable."`
	LoginName                       *string                      `json:"login_name,omitempty" description:"The name of the login user"`
	AppName                         *string                      `json:"app_name,omitempty" description:"Name of the app involved in the event, if applicable."`
	AuthenticationFactorDescription *string                      `json:"authentication_factor_description,omitempty" description:"More details about the authentication factor used."`
	CertificateName                 *string                      `json:"certificate_name,omitempty" description:"The name of the certificate that was included in the request."`
	CertificateID                   *string                      `json:"certificate_id,omitempty" description:"The ID of the certificate that was included in the request."`
	AssumedBySuperadminOrReseller   *bool                        `json:"assumed_by_superadmin_or_reseller,omitempty" description:"Indicates that the operation was performed by superadmin or reseller."`
	DirectoryName                   *string                      `json:"directory_name,omitempty" description:"The directory name."`
	ActorUserID                     *int                         `json:"actor_user_id,omitempty" description:"ID of the user whose action triggered the event."`
	UserName                        *string                      `json:"user_name,omitempty" description:"Name of the user that was acted upon to trigger the event."`
	MappingID                       *int                         `json:"mapping_id,omitempty" description:"The ID of the mapping included in the operation."`
	RadiusConfigID                  *int                         `json:"radius_config_id,omitempty" description:"The ID of the Radius configuration included in the operation."`
	RiskScore                       *int                         `json:"risk_score,omitempty" description:"The higher thiss number, the higher the risk."`
	OtpDeviceID                     *int                         `json:"otp_device_id,omitempty" description:"ID of a device involved in the event."`
	ImportedUserID                  *int                         `json:"imported_user_id,omitempty" description:"The ID of the imported user."`
	Resolution                      *int                         `json:"resolution,omitempty" description:"The resolution."`
	DirectoryID                     *int                         `json:"directory_id,omitempty" description:"The directory ID."`
	AuthenticationFactorID          *int                         `json:"authentication_factor_id,omitempty" description:"The ID of the authentication factor used."`
	RiskCookieID                    *string                      `json:"risk_cookie_id,omitempty" description:"The ID of the risk cookie."`
	AppID                           *int                         `json:"app_id,omitempty" description:"ID of the app involved in the event, if applicable."`
	CustomMessage                   *string                      `json:"custom_message,omitempty" description:"More details about the event."`
	BrowserFingerprint              *string                      `json:"browser_fingerprint,omitempty" description:"The fingerprint of the browser."`
	OtpDeviceName                   *string                      `json:"otp_device_name,omitempty" description:"Name of a device involved in the event."`
	ActorUserName                   *string                      `json:"actor_user_name,omitempty" description:"First and last name of the user whose action triggered the event."`
	ActorSystem                     *string                      `json:"actor_system,omitempty" description:"Acting system that triggered the event when the actor is not a user."`
	UserFieldName                   *string                      `json:"user_field_name,omitempty" description:"The name of the custom user field."`
	UserFieldID                     *string                      `json:"user_field_id,omitempty" description:"The ID of the custom user field."`
	AssumingActingUserID            *int                         `json:"assuming_acting_user_id,omitempty" description:"ID of the user who assumed the role of the acting user to trigger the event, if applicable."`
	APICredentialName               *string                      `json:"api_credential_name,omitempty" description:"The name of the API credential used."`
	ImportedUserName                *string                      `json:"imported_user_name,omitempty" description:"The name of the imported user."`
	NoteTitle                       *string                      `json:"note_title,omitempty" description:"The title of the note."`
	TrustedIdpName                  *string                      `json:"trusted_idp_name,omitempty" description:"The name of the trusted IDP."`
	PolicyID                        *int                         `json:"policy_id,omitempty" description:"ID of the policy involved in the event."`
	RoleName                        *string                      `json:"role_name,omitempty" description:"Name of a role involved in the event."`
	ResolvedByUserID                *int                         `json:"resolved_by_user_id,omitempty" description:"The ID of the user that resolved the issue."`
	GroupID                         *int                         `json:"group_id,omitempty" description:"ID of a group involved in the event."`
	ClientID                        *string                      `json:"client_id,omitempty" description:"Client ID used to generate the access token that made the API call that generated the event."`
	IPAddr                          *string                      `json:"ipaddr,omitempty" description:"IP address of the machine used to trigger the event."`
	Notes                           *string                      `json:"notes,omitempty" description:"More details about the event."`
	EventTypeID                     *int                         `json:"event_type_id" validate:"required" description:"Type of event triggered."`
	UserID                          *int                         `json:"user_id,omitempty" description:"ID of the user that was acted upon to trigger the event."`
	RiskReasons                     *string                      `json:"risk_reasons,omitempty" description:"This is not an exhaustive list of the reasons for the risk score and should only be used as a guide"`
	ProxyAgentName                  *string                      `json:"proxy_agent_name,omitempty" description:"The name of the proxy agent."`
	PolicyType                      *string                      `json:"policy_type,omitempty" description:"The type of the policy."`
	RoleID                          *int                         `json:"role_id,omitempty" description:"ID of a role involved in the event."`
	UserAgent                       *string                      `json:"user_agent,omitempty" description:"The user agent from which the request was invoke"`
	PrivilegeName                   *string                      `json:"privilege_name,omitempty" description:"The name of the privilege."`
	GroupName                       *string                      `json:"group_name,omitempty" description:"Name of a group involved in the event."`
	Entity                          *string                      `json:"entity,omitempty" description:"The entity involved in this request."`
	ResourceTypeID                  *int                         `json:"resource_type_id,omitempty" description:"ID of the resource (user, role, group, and so forth) associated with the event."`
	MappingName                     *string                      `json:"mapping_name,omitempty" description:"The name of the mapping."`
	TaskName                        *string                      `json:"task_name,omitempty" description:"The name of the task."`
	AuthenticationFactorType        *int                         `json:"authentication_factor_type,omitempty" description:"The type of the authentication type."`
	RadiusConfigName                *string                      `json:"radius_config_name,omitempty" description:"The name of the Radius configuration used."`
	PolicyName                      *string                      `json:"policy_name,omitempty" description:"Name of the policy involved in the event."`
	PrivilegeID                     *int                         `json:"privilege_id,omitempty" description:"The id of the privilege."`
	DirectorySyncRunID              *int                         `json:"directory_sync_run_id,omitempty" description:"Directory sync run ID."`
	OperationName                   *string                      `json:"operation_name,omitempty" description:"The name of the operation"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// OneLogin parser parses OneLogin logs
type OneLoginParser struct{}

func (p *OneLoginParser) New() parsers.LogParser {
	return &OneLoginParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *OneLoginParser) Parse(log string) ([]*parsers.PantherLog, error) {
	var event OneLogin
	err := jsoniter.UnmarshalFromString(log, &event)
	if err != nil {
		return nil, err
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}
	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *OneLoginParser) LogType() string {
	return TypeOneLogin
}

func (event *OneLogin) updatePantherFields(p *OneLoginParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.EventTimestamp), event)
	event.AppendAnyIPAddressPtr(event.IPAddr)
}
