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

// nolint:lll
var (
	TypeUserIdentity = mustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".UserIdentity",
		Description:  `The UserIdentity event is generated when a user logs in to a host. It conveys important security-related characteristics associated with a user to the CrowdStrike cloud, such as the user name. It’s normally generated once per security principal, and is thus not on its own a sign of a suspicious activity. Available for Mac & Windows platforms.`,
		ReferenceURL: `https://developer.crowdstrike.com/crowdstrike/page/event-explorer#section-event-UserIdentity`,
		NewEvent:     func() interface{} { return &UserIdentity{} },
	})

	TypeGroupIdentity = mustBuild(logtypes.ConfigJSON{
		Name:         TypePrefix + ".GroupIdentity",
		Description:  `Provides the sensor boot unique mapping between GID, AuthenticationId, UserPrincipal, and UserSid. Available only for the Mac platform.`,
		ReferenceURL: `https://developer.crowdstrike.com/crowdstrike/page/event-explorer#section-event-GroupIdentity`,
		NewEvent:     func() interface{} { return &GroupIdentity{} },
	})
)

// nolint:lll
type UserIdentity struct {
	ContextEvent
	EventSimpleName pantherlog.String `json:"event_simpleName" validate:"required,eq=UserIdentity" description:"Event Name"`
	CommonIdentityFields

	// Mac Only
	AuthenticationUUID         pantherlog.String `json:"AuthenticationUuid"`
	AuthenticationUUIDAsString pantherlog.String `json:"AuthenticationUuidAsString"`
	UID                        pantherlog.Int64  `json:"UID" description:"The User ID."`

	// Windows only
	UserName              pantherlog.String `json:"UserName" panther:"username"`
	UserCanonical         pantherlog.String `json:"UserCanonical"`
	LogonID               pantherlog.String `json:"LogonId"`
	LogonDomain           pantherlog.String `json:"LogonDomain"`
	AuthenticationPackage pantherlog.String `json:"AuthenticationPackage"`
	LogonType             pantherlog.Int32  `json:"LogonType" description:"Values: INTERACTIVE (2), NETWORK (3), BATCH (4), SERVICE (5), PROXY (6), UNLOCK (7), NETWORK_CLEARTEXT (8), CACHED_UNLOCK (13), NEW_CREDENTIALS (9), REMOTE_INTERACTIVE (10), CACHED_INTERACTIVE (11), CACHED_REMOTE_INTERACTIVE (12)"`
	LogonTime             pantherlog.Time   `json:"LogonTime" tcodec:"unix"`
	LogonServer           pantherlog.String `json:"LogonServer"`
	UserFlags             pantherlog.Int64  `json:"UserFlags" description:"Values: LOGON_OPTIMIZED (0x4000), LOGON_WINLOGON (0x8000), LOGON_PKINIT (0x10000), LOGON_NOT_OPTIMIZED (0x20000)"`
	PasswordLastSet       pantherlog.Time   `json:"PasswordLastSet" tcodec:"unix"`
	RemoteAccount         pantherlog.Int32  `json:"RemoteAccount"`
	UserIsAdmin           pantherlog.Int32  `json:"UserIsAdmin"`
	SessionID             pantherlog.String `json:"SessionId" panther:"trace_id"`
	UserLogonFlags        pantherlog.Int32  `json:"UserLogonFlags" description:"Values: LOGON_IS_SYNTHETIC (0x00000001), USER_IS_ADMIN (0x00000002), USER_IS_LOCAL (0x00000004), USER_IS_BUILT_IN (0x00000008), USER_IDENTITY_MISSING (0x00000010)"`
}

// nolint:lll
type GroupIdentity struct {
	ContextEvent
	EventSimpleName            pantherlog.String `json:"event_simpleName" validate:"required,eq=GroupIdentity" description:"Event Name"`
	GID                        pantherlog.Int64  `json:"GID" validate:"required" description:"The user Group ID."`
	AuthenticationUUID         pantherlog.String `json:"AuthenticationUuid" validate:"required"`
	AuthenticationUUIDAsString pantherlog.String `json:"AuthenticationUuidAsString" validate:"required"`
	CommonIdentityFields
}

// nolint:lll
type CommonIdentityFields struct {
	AuthenticationID pantherlog.Int32  `json:"AuthenticationId" validate:"required" description:"Values: INVALID_LUID (0), NETWORK_SERVICE (996), LOCAL_SERVICE (997), SYSTEM (999), RESERVED_LUID_MAX (1000)"`
	UserPrincipal    pantherlog.String `json:"UserPrincipal" validate:"required"`
	UserSid          pantherlog.String `json:"UserSid" validate:"required" description:"The User Security Identifier (UserSID) of the user who executed the command. A UserSID uniquely identifies a user in a system."`
}
