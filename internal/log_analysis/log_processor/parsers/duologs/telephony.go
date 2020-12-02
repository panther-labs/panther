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

const TypeTelephony = "Duo.Telephony"

// nolint:lll
type TelephonyLog struct {
	Context      pantherlog.String `json:"context" description:"How this telephony event was initiated. One of: \"administrator login\", \"authentication\", \"enrollment\", or \"verify\"."`
	Credits      pantherlog.Int32  `json:"credits" description:"How many telephony credits this event cost."`
	ISOTimestamp pantherlog.Time   `json:"isotimestamp" validate:"required" event_time:"true" tcodec:"rfc3339" description:"ISO8601 timestamp of the event."`
	Phone        pantherlog.String `json:"phone" validate:"required" description:"The phone number that initiated this event."`
	Timestamp    pantherlog.Time   `json:"timestamp" tcodec:"unix" description:"Unix timestamp of the event."`
	Type         pantherlog.String `json:"type" validate:"required" description:" The event type. Either \"sms\" or \"phone\"."`
}
