package oneloginlogs

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

const TypeOneLogin = "OneLogin.Events"

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("OneLogin", logtypes.ConfigJSON{
	Name: TypeOneLogin,
	Description: `OneLogin provides single sign-on and identity management for organizations
Panther Enterprise Only
`,
	ReferenceURL: `https://developers.onelogin.com/api-docs/1/events/event-resource`,
	NewEvent: func() interface{} {
		return &OneLogin{}
	},
})

// nolint:lll
type OneLogin struct {
	UUID                            pantherlog.String `json:"uuid" validate:"required,uuid" description:"The Universal Unique Identifier for this message generated by OneLogin."`
	AccountID                       pantherlog.Int64  `json:"account_id" validate:"required" description:"Account that triggered the event."`
	EventTimestamp                  pantherlog.Time   `json:"event_timestamp" event_time:"true" tcodec:"layout=2006-01-02 15:04:05 MST" validate:"required" description:"Time and date at which the event was created. This value is autogenerated by OneLogin."`
	ErrorDescription                pantherlog.String `json:"error_description" description:"Provisioning error details, if applicable."`
	LoginName                       pantherlog.String `json:"login_name" description:"The name of the login user"`
	AppName                         pantherlog.String `json:"app_name" description:"Name of the app involved in the event, if applicable."`
	AuthenticationFactorDescription pantherlog.String `json:"authentication_factor_description" description:"More details about the authentication factor used."`
	CertificateName                 pantherlog.String `json:"certificate_name" description:"The name of the certificate that was included in the request."`
	CertificateID                   pantherlog.String `json:"certificate_id" description:"The ID of the certificate that was included in the request."`
	AssumedBySuperadminOrReseller   pantherlog.Bool   `json:"assumed_by_superadmin_or_reseller" description:"Indicates that the operation was performed by superadmin or reseller."`
	DirectoryName                   pantherlog.String `json:"directory_name" description:"The directory name."`
	ActorUserID                     pantherlog.Int64  `json:"actor_user_id" description:"ID of the user whose action triggered the event."`
	UserName                        pantherlog.String `json:"user_name" panther:"username" description:"Name of the user that was acted upon to trigger the event."`
	MappingID                       pantherlog.Int64  `json:"mapping_id" description:"The ID of the mapping included in the operation."`
	RadiusConfigID                  pantherlog.Int64  `json:"radius_config_id" description:"The ID of the Radius configuration included in the operation."`
	RiskScore                       pantherlog.Int64  `json:"risk_score" description:"The higher thiss number, the higher the risk."`
	OtpDeviceID                     pantherlog.Int64  `json:"otp_device_id" description:"ID of a device involved in the event."`
	ImportedUserID                  pantherlog.Int64  `json:"imported_user_id" description:"The ID of the imported user."`
	Resolution                      pantherlog.Int64  `json:"resolution" description:"The resolution."`
	DirectoryID                     pantherlog.Int64  `json:"directory_id" description:"The directory ID."`
	AuthenticationFactorID          pantherlog.Int64  `json:"authentication_factor_id" description:"The ID of the authentication factor used."`
	RiskCookieID                    pantherlog.String `json:"risk_cookie_id" description:"The ID of the risk cookie."`
	AppID                           pantherlog.Int64  `json:"app_id" description:"ID of the app involved in the event, if applicable."`
	CustomMessage                   pantherlog.String `json:"custom_message" description:"More details about the event."`
	BrowserFingerprint              pantherlog.String `json:"browser_fingerprint" description:"The fingerprint of the browser."`
	OtpDeviceName                   pantherlog.String `json:"otp_device_name" description:"Name of a device involved in the event."`
	ActorUserName                   pantherlog.String `json:"actor_user_name" panther:"username" description:"First and last name of the user whose action triggered the event."`
	ActorSystem                     pantherlog.String `json:"actor_system" description:"Acting system that triggered the event when the actor is not a user."`
	UserFieldName                   pantherlog.String `json:"user_field_name" description:"The name of the custom user field."`
	UserFieldID                     pantherlog.String `json:"user_field_id" description:"The ID of the custom user field."`
	AssumingActingUserID            pantherlog.Int64  `json:"assuming_acting_user_id" description:"ID of the user who assumed the role of the acting user to trigger the event, if applicable."`
	APICredentialName               pantherlog.String `json:"api_credential_name" description:"The name of the API credential used."`
	ImportedUserName                pantherlog.String `json:"imported_user_name" panther:"username" description:"The name of the imported user."`
	NoteTitle                       pantherlog.String `json:"note_title" description:"The title of the note."`
	TrustedIdpName                  pantherlog.String `json:"trusted_idp_name" description:"The name of the trusted IDP."`
	PolicyID                        pantherlog.Int64  `json:"policy_id" description:"ID of the policy involved in the event."`
	RoleName                        pantherlog.String `json:"role_name" description:"Name of a role involved in the event."`
	ResolvedByUserID                pantherlog.Int64  `json:"resolved_by_user_id" description:"The ID of the user that resolved the issue."`
	GroupID                         pantherlog.Int64  `json:"group_id" description:"ID of a group involved in the event."`
	ClientID                        pantherlog.String `json:"client_id" description:"Client ID used to generate the access token that made the API call that generated the event."`
	IPAddr                          pantherlog.String `json:"ipaddr" panther:"ip" description:"IP address of the machine used to trigger the event."`
	Notes                           pantherlog.String `json:"notes" description:"More details about the event."`
	EventTypeID                     pantherlog.Int64  `json:"event_type_id" validate:"required" description:"Type of event triggered."`
	UserID                          pantherlog.Int64  `json:"user_id" description:"ID of the user that was acted upon to trigger the event."`
	RiskReasons                     pantherlog.String `json:"risk_reasons" description:"This is not an exhaustive list of the reasons for the risk score and should only be used as a guide"`
	ProxyAgentName                  pantherlog.String `json:"proxy_agent_name" description:"The name of the proxy agent."`
	PolicyType                      pantherlog.String `json:"policy_type" description:"The type of the policy."`
	RoleID                          pantherlog.Int64  `json:"role_id" description:"ID of a role involved in the event."`
	UserAgent                       pantherlog.String `json:"user_agent" description:"The user agent from which the request was invoke"`
	PrivilegeName                   pantherlog.String `json:"privilege_name" description:"The name of the privilege."`
	GroupName                       pantherlog.String `json:"group_name" description:"Name of a group involved in the event."`
	Entity                          pantherlog.String `json:"entity" description:"The entity involved in this request."`
	ResourceTypeID                  pantherlog.Int64  `json:"resource_type_id" description:"ID of the resource (user, role, group, and so forth) associated with the event."`
	MappingName                     pantherlog.String `json:"mapping_name" description:"The name of the mapping."`
	TaskName                        pantherlog.String `json:"task_name" description:"The name of the task."`
	AuthenticationFactorType        pantherlog.Int64  `json:"authentication_factor_type" description:"The type of the authentication type."`
	RadiusConfigName                pantherlog.String `json:"radius_config_name" description:"The name of the Radius configuration used."`
	PolicyName                      pantherlog.String `json:"policy_name" description:"Name of the policy involved in the event."`
	PrivilegeID                     pantherlog.Int64  `json:"privilege_id" description:"The id of the privilege."`
	DirectorySyncRunID              pantherlog.Int64  `json:"directory_sync_run_id" description:"Directory sync run ID."`
	OperationName                   pantherlog.String `json:"operation_name" description:"The name of the operation"`
}
