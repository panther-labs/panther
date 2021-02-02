package crowdstrikelogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

var (
	TypeAppInfo = logtypes.MustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".AppInfo",
		Description:  "Detected Application Information provided by Falcon Discover",
		ReferenceURL: "https://developer.crowdstrike.com/crowdstrike/docs/falcon-data-replicator-guide#section-appinfo",
		NewEvent:     func() interface{} { return &AppInfo{} },
	})

	TypeUserInfo = logtypes.MustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".UserInfo",
		Description:  "User Account & Logon information provided by Falcon Discover",
		ReferenceURL: "https://developer.crowdstrike.com/crowdstrike/docs/falcon-data-replicator-guide#section-userinfo",
		NewEvent:     func() interface{} { return &UserInfo{} },
	})
)

// nolint:lll
type AppInfo struct {
	Time            pantherlog.Time   `json:"_time" validate:"required" tcodec:"unix" event_time:"true" description:"The host's local time in epoch format."`
	CID             pantherlog.String `json:"cid" validate:"required" description:"The customer ID."`
	CompanyName     pantherlog.String `json:"CompanyName" validate:"required" description:"The name of the company."`
	DetectionCount  pantherlog.Int64  `json:"detectioncount" validate:"required" description:"The number of detections."`
	FileName        pantherlog.String `json:"FileName" validate:"required" description:"The name of the file."`
	SHA256HashData  pantherlog.String `json:"SHA256HashData" validate:"required" panther:"sha256" description:"The file hash bashed on SHA-256."`
	FileDescription pantherlog.String `json:"FileDescription" description:"The description of the file, if any."`
	FileVersion     pantherlog.String `json:"FileVersion" description:"The version of the file."`
	ProductName     pantherlog.String `json:"ProductName" description:"The name of the product."`
	ProductVersion  pantherlog.String `json:"ProductVersion" description:"The version of the product."`
}

// nolint:lll
type UserInfo struct {
	Time                  pantherlog.Time   `json:"_time" validate:"required" tcodec:"unix" event_time:"true" description:"The host's local time in epoch format."`
	CID                   pantherlog.String `json:"cid" validate:"required" description:"The customer ID."`
	AccountType           pantherlog.String `json:"AccountType" validate:"required" description:"The type of account set for the user: 'Domain User', 'Domain Administrator', 'Local User'."`
	DomainUser            pantherlog.String `json:"DomainUser" validate:"required" description:"Indicates if the user's credentials are part of a domain controller: 'Yes', 'No'."`
	UserName              pantherlog.String `json:"UserName" validate:"required" panther:"username" description:"The username of the system."`
	UserSidReadable       pantherlog.String `json:"UserSid_readable" validate:"required" description:"The user SID associated with this process."`
	LastLoggedOnHost      pantherlog.String `json:"LastLoggedOnHost" description:"The host that was last logged into the system."`
	LocalAdminAccess      pantherlog.String `json:"LocalAdminAccess" description:"Indicates whether a local user is an admin: 'Yes', 'No'."`
	LoggedOnHostCount     pantherlog.Int32  `json:"LoggedOnHostCount" description:"The number of hosts logged in at _time."`
	LogonInfo             pantherlog.String `json:"LogonInfo" description:"The login information."`
	LogonTime             pantherlog.Time   `json:"LogonTime" tcodec:"unix" description:"The last login time by this user in epoch format."`
	LogonType             pantherlog.String `json:"LogonType" description:"Values defined as follows, INTERACTIVE: The security principal is logging on interactively, NETWORK: The security principal is logging on using a network, TERMINAL SERVER: The security principal has logged in via a terminal server."`
	MonthSinceReset       pantherlog.Int32  `json:"monthsincereset" description:"The number of months since this user's password was last reset."`
	PasswordLastSet       pantherlog.Time   `json:"PasswordLastSet" tcodec:"unix" description:"The last time in epoch format that this user's password in the system was set."`
	User                  pantherlog.String `json:"User" description:"A system username with domain."`
	UserIsAdmin           pantherlog.Int8   `json:"UserIsAdmin" description:"Indicates whether the user account has administrator privileges."`
	UserLogonFlagsDecimal pantherlog.Int32  `json:"UserLogonFlags_decimal" description:"A bitfield for various bits of a UserLogon, or failed user logon."`
}
