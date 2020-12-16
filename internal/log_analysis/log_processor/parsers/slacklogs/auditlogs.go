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

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

const TypeAuditLogs = "Slack.AuditLogs"

// nolint:lll
type AuditLog struct {
	ID         pantherlog.String     `json:"id" validate:"required" description:"The event id"`
	DateCreate pantherlog.Time       `json:"date_create" validate:"required" tcodec:"unix" event_time:"true" description:"Creation timestamp for the event"`
	Action     pantherlog.String     `json:"action" validate:"required" description:"The action performed. See https://api.slack.com/enterprise/audit-logs#audit_logs_actions"`
	Actor      Actor                 `json:"actor" validate:"required" description:"An actor will always be a user on a workspace and will be identified by their user ID, such as W123AB456."`
	Entity     Entity                `json:"entity" validate:"required" description:"An entity is the thing that the actor has taken the action upon and it will be the Slack ID of the thing."`
	Context    Context               `json:"context" validate:"required" description:"Context is the location that the actor took the action on the entity. It will always be either a Workspace or an Enterprise, with the appropriate ID."`
	Details    pantherlog.RawMessage `json:"details" description:"Additional details about the audit log event"`
}

// nolint:lll
type Entity struct {
	Type       pantherlog.String `json:"type" validate:"required" description:"The type of item that was affected by the action (user,channel,file,app,workspace,enterprise,message,workflow)"`
	User       *User             `json:"user" description:"Information about the affected user"`
	Channel    *Channel          `json:"channel" description:"Information about the affected channel"`
	File       *File             `json:"file" description:"Information about the affected file"`
	App        *App              `json:"app" description:"Information about the affected app"`
	Workspace  *Workspace        `json:"workspace" description:"Information about the affected workspace"`
	Enterprise *Enterprise       `json:"enterprise" description:"Information about the affected enterprise"`
	Workflow   *Workflow         `json:"workflow" description:"Information about the affected workflow"`
	Message    *Message          `json:"message" description:"Information about the affected message"`
}

// nolint:lll
type Actor struct {
	Type pantherlog.String `json:"type" validate:"required,eq=user" description:"The type of actor (always user)"`
	User User              `json:"user" description:"Information about the user"`
}

// nolint:lll
type User struct {
	ID    pantherlog.String `json:"id" validate:"required" description:"The id of the user ('USLACKUSER' if no user performed the action)"`
	Name  pantherlog.String `json:"name" panther:"username" description:"The user's display name"`
	Email pantherlog.String `json:"email" panther:"email" description:"The user's email"`
	Team  pantherlog.String `json:"team" description:"The user's team"`
}

// nolint:lll
type File struct {
	ID       pantherlog.String `json:"id" validate:"required" description:"The id of the file"`
	Name     pantherlog.String `json:"name" description:"The filename"`
	Title    pantherlog.String `json:"title" description:"The file title"`
	Filetype pantherlog.String `json:"filetype" description:"The filetype"`
}

// nolint:lll
type Channel struct {
	ID          pantherlog.String   `json:"id" validate:"required" description:"The id of the channel"`
	Name        pantherlog.String   `json:"name" description:"The name of the channel"`
	Privacy     pantherlog.String   `json:"privacy" description:"The privacy mode of the channel"`
	Shared      pantherlog.Bool     `json:"is_shared" description:"Whether the channel is shared"`
	OrgShared   pantherlog.Bool     `json:"is_org_shared" description:"Whether the channel is shared in the organisation"`
	SharedTeams []pantherlog.String `json:"teams_shared_with" description:"The teams the channel is shared with"`
}

// nolint:lll
type App struct {
	ID                pantherlog.String   `json:"id" validate:"required" description:"The id of the app"`
	Name              pantherlog.String   `json:"name" description:"The name of the app"`
	Distributed       pantherlog.Bool     `json:"is_distributed" description:"Whether the app is distributed"`
	DirectoryApproved pantherlog.Bool     `json:"is_directory_approved" description:"Whether the app is in the approved apps directory"`
	Scopes            []pantherlog.String `json:"scopes" description:"The OAuth2 scopes the app requires"`
}

// nolint:lll
type Workspace struct {
	ID     pantherlog.String `json:"id" validate:"required" description:"The id of the workspace"`
	Name   pantherlog.String `json:"name" description:"The name of the workspace"`
	Domain pantherlog.String `json:"domain" description:"The workspace domain"`
}

// nolint:lll
type Workflow struct {
	ID   pantherlog.String `json:"id" validate:"required" description:"The id of the workflow"`
	Name pantherlog.String `json:"name" description:"The name of the workflow"`
}

// nolint:lll
type Message struct {
	Team    pantherlog.String `json:"team" description:"The team the message was posted in"`
	Channel pantherlog.String `json:"channel" description:"The channel the message was posted on"`
	// TODO: Get samples to find the format
	Timestamp pantherlog.String `json:"timestamp" description:"The timestamp of the message"`
}

// nolint:lll
type Enterprise struct {
	ID     pantherlog.String `json:"id" validate:"required" description:"The id of the enterprise"`
	Name   pantherlog.String `json:"name" description:"The name of the enterprise"`
	Domain pantherlog.String `json:"domain" description:"The enterprise domain"`
}

// nolint:lll
type Context struct {
	UserAgent pantherlog.String `json:"ua" description:"The user agent used for the action"`
	IPAddress pantherlog.String `json:"ip_address" panther:"ip" description:"The ip address the action was performed from"`
	Location  Location          `json:"location" description:"The location that the actor took the action on the entity."`
}

// nolint:lll
type Location struct {
	Type   pantherlog.String `json:"type" validate:"required" description:"The location type. It will always be either a Workspace or an Enterprise"`
	ID     pantherlog.String `json:"id" validate:"required" description:"The location id"`
	Domain pantherlog.String `json:"domain" description:"The location domain"`
	Name   pantherlog.String `json:"name" description:"The location name"`
}
