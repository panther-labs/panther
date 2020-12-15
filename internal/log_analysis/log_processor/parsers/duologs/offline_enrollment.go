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

const TypeOfflineEnrollment = "Duo.OfflineEnrollment"

// nolint:lll
type OfflineEnrollmentLog struct {
	Action       pantherlog.String `json:"action" validate:"oneof=o2fa_user_provisioned o2fa_user_deprovisioned o2fa_user_reenrolled" description:"The offline enrollment operation. One of \"o2fa_user_provisioned\", \"o2fa_user_deprovisioned\", or \"o2fa_user_reenrolled\"."`
	Description  pantherlog.String `json:"description" description:"Information about the Duo Windows Logon client system as reported by the application."`
	ISOTimestamp pantherlog.Time   `json:"isotimestamp" validate:"required" event_time:"true" tcodec:"rfc3339" description:"ISO8601 timestamp of the event."`
	Object       pantherlog.String `json:"object" validate:"required" description:"The Duo Windows Logon integration's name."`
	Timestamp    pantherlog.Time   `json:"timestamp" tcodec:"unix" description:"Unix timestamp of the event."`
	UserName     pantherlog.String `json:"username" panther:"username" validate:"required" description:"The Duo username."`
}

// nolint:lll
type Description struct {
	UserAgent pantherlog.String `json:"user_agent" description:"The Duo Windows Logon application version information and the Windows OS version and platform information."`
	HostName  pantherlog.String `json:"hostname" description:" The host name of the system where Duo Windows Logon is installed."`
	Factor    pantherlog.String `json:"factor" description:" The type of authenticator used for offline access. One of \"duo_otp\" or \"security_key\"."`
}
