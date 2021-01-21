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

const TypeIntegrationLogs = "Slack.IntegrationLogs"

//nolint:lll
type IntegrationLog struct {
	UserID            pantherlog.String `json:"user_id" validate:"required" description:"The id of the user performing the action."`
	UserName          pantherlog.String `json:"user_name" panther:"username" description:"The username of the user performing the action."`
	ServiceID         pantherlog.String `json:"service_id" description:"The service id for which this log is about."`
	ServiceType       pantherlog.String `json:"service_type" description:"The service type for which this log is about."`
	AppID             pantherlog.String `json:"app_id" description:"The app id for which this log is about."`
	AppType           pantherlog.String `json:"app_type" description:"The app type for which this log is about."`
	Date              pantherlog.Time   `json:"date" validate:"required" tcodec:"unix" event_time:"true" description:"The date when the action happened."`
	ChangeType        pantherlog.String `json:"change_type" validate:"required" description:"The type of this action (added, removed, enabled, disabled, updated)."`
	Scope             pantherlog.String `json:"scope" validate:"required" description:"The scope used for this action."`
	Channel           pantherlog.String `json:"channel" description:"The related channel."`
	Reason            pantherlog.String `json:"reason" description:"The reason of the disable action, populated if this event refers to such an action."`
	RSSFeed           pantherlog.Bool   `json:"rss_feed" description:"True if this log entry is an RSS feed. If true, more RSS feed related fields will be present."`
	RSSFeedChangeType pantherlog.Bool   `json:"rss_feed_change_type" description:"The change type for the RSS feed."`
	RSSFeedTitle      pantherlog.Bool   `json:"rss_feed_title" description:"The title of the RSS feed."`
	RSSFeedURL        pantherlog.Bool   `json:"rss_feed_url" description:"The url of the RSS feed."`
}
