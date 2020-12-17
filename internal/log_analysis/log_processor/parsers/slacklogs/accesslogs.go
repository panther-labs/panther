package slacklogs

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

const TypeAccessLogs = "Slack.AccessLogs"

//nolint:lll
type AccessLog struct {
	UserID    pantherlog.String `json:"user_id" validate:"required" description:"The id of the user accessing Slack."`
	UserName  pantherlog.String `json:"username" panther:"username" description:"The username of the user accessing Slack."`
	DateFirst pantherlog.Time   `json:"date_first" validate:"required" tcodec:"unix" description:"Unix timestamp of the first access log entry for this user, IP address, and user agent combination."`
	DateLast  pantherlog.Time   `json:"date_last" validate:"required" tcodec:"unix" event_time:"true" description:"Unix timestamp of the most recent access log entry for this user, IP address, and user agent combination."`
	Count     pantherlog.Int64  `json:"count" validate:"required" description:"The total number of access log entries for that combination."`
	IP        pantherlog.String `json:"ip" validate:"required" panther:"ip" description:"The IP address of the device used to access Slack."`
	UserAgent pantherlog.String `json:"user_agent" description:"The reported user agent string from the browser or client application."`
	ISP       pantherlog.String `json:"isp" description:"Best guess at the internet service provider owning the IP address."`
	Country   pantherlog.String `json:"country" description:"Best guesses on where the access originated, based on the IP address."`
	Region    pantherlog.String `json:"region" description:"Best guesses on where the access originated, based on the IP address."`
}
