package duologs

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

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"

const TypeAuthentication = "Duo.Authentication"

// nolint:lll
type AuthenticationLog struct {
	AccessDevice *AccessDevice     `json:"access_device" description:"Browser, plugin, and operating system information for the endpoint used to access the Duo-protected resource. Values present only when the application accessed features Duo’s inline browser prompt."`
	Alias        pantherlog.String `json:"alias" panther:"username" description:"The username alias used to log in. No value if the user logged in with their username instead of a username alias."`
	Application  *Application      `json:"application" description:"Information about the application accessed."`
	AuthDevice   *AuthDevice       `json:"auth_device" description:"Information about the device used to approve or deny authentication."`
	Email        pantherlog.String `json:"email" panther:"email" description:"The email address of the user, if known to Duo, otherwise none."`
	EventType    pantherlog.String `json:"event_type" description:"The type of activity logged. one of: \"authentication\" or \"enrollment\"."`
	Factor       pantherlog.String `json:"factor" description:"The authentication factor. One of: \"phone_call\", \"passcode\", \"yubikey_passcode\", \"digipass_go_7_token\", \"hardware_token\", \"duo_mobile_passcode\", \"bypass_code\", \"sms_passcode\", \"sms_refresh\", \"duo_push\", \"u2f_token\", \"remembered_device\", or \"trusted_network\"."`
	ISOTimestamp pantherlog.Time   `json:"isotimestamp" validate:"required" event_time:"true" tcodec:"rfc3339" description:"ISO8601 timestamp of the event."`
	OODSoftware  pantherlog.String `json:"ood_software" description:"If authentication was denied due to out-of-date software, shows the name of the software, i.e. \"Chrome\", \"Flash\", etc. No value if authentication was successful or authentication denial was not due to out-of-date software."`
	Reason       pantherlog.String `json:"reason" description:"Provide the reason for the authentication attempt result. If result is \"SUCCESS\" then one of: \"allow_unenrolled_user\", \"allowed_by_policy\", \"allow_unenrolled_user_on_trusted_network\", \"bypass_user\", \"remembered_device\", \"trusted_location\", \"trusted_network\", \"user_approved\", \"valid_passcode\". If result is \"FAILURE\" then one of: \"anonymous_ip\", \"anomalous_push\", \"could_not_determine_if_endpoint_was_trusted\", \"denied_by_policy\", \"denied_network\", \"deny_unenrolled_user\", \"endpoint_is_not_in_management_system\", \"endpoint_failed_google_verification\", \"endpoint_is_not_trusted\", \"factor_restricted\", \"invalid_management_certificate_collection_state\", \"invalid_device\", \"invalid_passcode\", \"invalid_referring_hostname_provided\", \"location_restricted\", \"locked_out\", \"no_activated_duo_mobile_account\", \"no_disk_encryption\", \"no_duo_certificate_present\", \"touchid_disabled\", \"no_referring_hostname_provided\", \"no_response\", \"no_screen_lock\", \"no_web_referer_match\", \"out_of_date\", \"platform_restricted\", \"rooted_device\", \"software_restricted\", \"user_cancelled\", \"user_disabled\", \"user_mistake\", \"user_not_in_permitted_group\", \"user_provided_invalid_certificate\", or \"version_restricted\". If result is \"ERROR\" then: \"error\". If result is \"FRAUD\" then: \"user_marked_fraud\"."`
	Result       pantherlog.String `json:"result" description:"The result of the authentication attempt. One of: \"SUCCESS\", \"FAILURE\", \"ERROR\", or \"FRAUD\"."`
	Timestamp    pantherlog.Time   `json:"timestamp" tcodec:"unix" description:"Unix timestamp of the event."`
	TxID         pantherlog.String `json:"txid" validate:"required" panther:"trace_id" description:"The transaction ID of the event."`
	User         User              `json:"user" description:"Information about the authenticating user."`
}

// nolint:lll
type AccessDevice struct {
	Browser        pantherlog.String `json:"browser" description:"The web browser used for access."`
	BrowserVersion pantherlog.String `json:"browser_version" description:"The browser version."`
	FlashVersion   pantherlog.String `json:"flash_version" description:"The Flash plugin version used, if present, otherwise \"uninstalled\"."`
	Hostname       pantherlog.String `json:"hostname" panther:"hostname" description:"The hostname, if present, otherwise \"null\"."`
	IP             pantherlog.String `json:"ip" panther:"ip" description:"The access device's IP address, if present, otherwise \"null\"."`
	//TODO: These fields are declared bool, but their description contradicts. Fix them when we hear back from Duo.
	IsEncryptionEnabled pantherlog.String   `json:"is_encryption_enabled" description:"Reports the disk encryption state as detected by the Duo Device Health app. One of \"true\", \"false\", or \"unknown\"."`
	IsFirewallEnabled   pantherlog.String   `json:"is_firewall_enabled" description:"Reports the firewall state as detected by the Duo Device Health app. One of \"true\", \"false\", or \"unknown\"."`
	IsPasswordSet       pantherlog.String   `json:"is_password_set" description:"Reports the system password state as detected by the Duo Device Health app. One of \"true\", \"false\", or \"unknown\"."`
	JavaVersion         pantherlog.String   `json:"java_version" description:"The Java plugin version used, if present, otherwise \"uninstalled\"."`
	Location            *Location           `json:"location" description:"The GeoIP location of the access device, if available. The response may not include all location parameters."`
	OS                  pantherlog.String   `json:"os" description:"The device operating system name."`
	OSVersion           pantherlog.String   `json:"os_version" description:"The device operating system version."`
	SecurityAgents      []pantherlog.String `json:"security_agents" description:"Reports the security agents present on the endpoint as detected by the Duo Device Health app."`
}

// nolint:lll
type Location struct {
	City    pantherlog.String `json:"city" description:"The city name."`
	Country pantherlog.String `json:"country" description:"The country code."`
	State   pantherlog.String `json:"state" description:"The state, county, province, or prefecture."`
}

// nolint:lll
type Application struct {
	Key  pantherlog.String `json:"key" description:"The application's integration_key."`
	Name pantherlog.String `json:"name" description:"The application's name."`
}

// nolint:lll
type AuthDevice struct {
	IP       pantherlog.String `json:"ip" panther:"ip" description:"The IP address of the authentication device."`
	Location *Location         `json:"location" description:"The GeoIP location of the authentication device, if available. May not include all location parameters."`
	Name     pantherlog.String `json:"name" description:"The name of the authentication device."`
}

// nolint:lll
type User struct {
	Groups []pantherlog.String `json:"groups" description:"Duo group membership information for the user."`
	Key    pantherlog.String   `json:"key" description:"The user's user_id."`
	Name   pantherlog.String   `json:"name" panther:"username" description:"The user's username."`
}
