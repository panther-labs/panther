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

const TypeAdministrator = "Duo.Administrator"

// nolint:lll
type AdministratorLog struct {
	//TODO: This event has the same fields as OfflineEnrollmentLog. To distinguish them, we validate that Action below
	// doesn't contain the values that OfflineEnrollmentLog.Action can take. If, however, Duo adds a value to the
	// values OfflineEnrollmentLog.Action can take, these events will be misclassified until we update our schemas.
	Action       pantherlog.String `json:"action" validate:"excludes=o2fa_user_provisioned o2fa_user_deprovisioned o2fa_user_reenrolled" description:"The type of change that was performed."`
	Description  pantherlog.String `json:"description" description:"String detailing what changed, either as free-form text or serialized JSON."`
	ISOTimestamp pantherlog.Time   `json:"isotimestamp" validate:"required" event_time:"true" tcodec:"rfc3339" description:"ISO8601 timestamp of the event."`
	Object       pantherlog.String `json:"object" validate:"required" description:"The object that was acted on. For example: \"jsmith\" (for users), \"(555) 713-6275 x456\" (for phones), or \"HOTP 8-digit 123456\" (for tokens)."`
	Timestamp    pantherlog.Time   `json:"timestamp" tcodec:"unix" description:"Unix timestamp of the event."`
	UserName     pantherlog.String `json:"username" validate:"required" panther:"username" description:"The full name of the administrator who performed the action in the Duo Admin Panel. If the action was performed with the API this will be \"API\". Automatic actions like deletion of inactive users have \"System\" for the username. Changes synchronized from Directory Sync will have a username of the form (example) \"AD Sync: name of directory\"."`
}
