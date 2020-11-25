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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeAuditLogs = "Slack.AuditLogs"

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("Slack", logtypes.Config{
	Name:         TypeAuditLogs,
	Description:  "Slack audit logs provide a view of the actions users perform in an Enterprise Grid organization.",
	ReferenceURL: "https://api.slack.com/enterprise/audit-logs",
	Schema:       AuditLog{},
	NewParser:    parsers.AdapterFactory(AuditParser{}),
})

// nolint:lll
type AuditLog struct {
	ID         string               `json:"id" validate:"required" description:"The event id"`
	DateCreate timestamp.UnixFloat  `json:"date_create" validate:"required" description:"Creation timestamp for the event"`
	Action     string               `json:"action" validate:"required" description:"The action performed. See https://api.slack.com/enterprise/audit-logs#audit_logs_actions"`
	Actor      Actor                `json:"actor" validate:"required" description:"An actor will always be a user on a workspace and will be identified by their user ID, such as W123AB456."`
	Entity     Entity               `json:"entity" validate:"required" description:"An entity is the thing that the actor has taken the action upon and it will be the Slack ID of the thing."`
	Context    Context              `json:"context" validate:"required" description:"Context is the location that the actor took the action on the entity. It will always be either a Workspace or an Enterprise, with the appropriate ID."`
	Details    *jsoniter.RawMessage `json:"details" description:"Additional details about the audit log event"`

	parsers.PantherLog
}

// nolint:lll
type Entity struct {
	Type       string      `json:"type" validate:"required" description:"The type of item that was affected by the action (user,channel,file,app,workspace,enterprise,message,workflow)"`
	User       *User       `json:"user,omitempty" description:"Information about the affected user"`
	Channel    *Channel    `json:"channel,omitempty" description:"Information about the affected channel"`
	File       *File       `json:"file,omitempty" description:"Information about the affected file"`
	App        *App        `json:"app,omitempty" description:"Information about the affected app"`
	Workspace  *Workspace  `json:"workspace,omitempty" description:"Information about the affected workspace"`
	Enterprise *Enterprise `json:"enterprise,omitempty" description:"Information about the affected enterprise"`
	Workflow   *Workflow   `json:"workflow,omitempty" description:"Information about the affected workflow"`
	Message    *Message    `json:"message,omitempty" description:"Information about the affected message"`
}

// nolint:lll
type Actor struct {
	Type string `json:"type" validate:"required,eq=user" description:"The type of actor (always user)"`
	User User   `json:"user" description:"Information about the user"`
}

// nolint:lll
type User struct {
	ID    string `json:"id" validate:"required" description:"The id of the user ('USLACKUSER' if no user performed the action)"`
	Name  string `json:"name,omitempty" description:"The user's display name"`
	Email string `json:"email,omitempty" description:"The user's email"`
	Team  string `json:"team,omitempty" description:"The user's team"`
}

// nolint:lll
type File struct {
	ID       string `json:"id" validate:"required" description:"The id of the file"`
	Name     string `json:"name,omitempty" description:"The filename"`
	Title    string `json:"title,omitempty" description:"The file title"`
	Filetype string `json:"filetype,omitempty" description:"The filetype"`
}

// nolint:lll
type Channel struct {
	ID          string   `json:"id" validate:"required" description:"The id of the channel"`
	Name        string   `json:"name,omitempty" description:"The name of the channel"`
	Privacy     string   `json:"privacy,omitempty" description:"The privacy mode of the channel"`
	Shared      bool     `json:"is_shared,omitempty" description:"Whether the channel is shared"`
	OrgShared   bool     `json:"is_org_shared,omitempty" description:"Whether the channel is shared in the organisation"`
	SharedTeams []string `json:"teams_shared_with,omitempty" description:"The teams the channel is shared with"`
}

// nolint:lll
type App struct {
	ID                string   `json:"id" validate:"required" description:"The id of the app"`
	Name              string   `json:"name,omitempty" description:"The name of the app"`
	Distributed       bool     `json:"is_distributed,omitempty" description:"Whether the app is distributed"`
	DirectoryApproved bool     `json:"is_directory_approved,omitempty" description:"Whether the app is in the approved apps directory"`
	Scopes            []string `json:"scopes,omitempty" description:"The OAuth2 scopes the app requires"`
}

// nolint:lll
type Workspace struct {
	ID     string `json:"id" validate:"required" description:"The id of the workspace"`
	Name   string `json:"name,omitempty" description:"The name of the workspace"`
	Domain string `json:"domain,omitempty" description:"The workspace domain"`
}

// nolint:lll
type Workflow struct {
	ID   string `json:"id" validate:"required" description:"The id of the workflow"`
	Name string `json:"name,omitempty" description:"The name of the workflow"`
}

// nolint:lll
type Message struct {
	Team    string `json:"team,omitempty" description:"The team the message was posted in"`
	Channel string `json:"channel,omitempty" description:"The channel the message was posted on"`
	// TODO: Get samples to find the format
	Timestamp string `json:"timestamp,omitempty" description:"The timestamp of the message"`
}

// nolint:lll
type Enterprise struct {
	ID     string `json:"id" validate:"required" description:"The id of the enterprise"`
	Name   string `json:"name,omitempty" description:"The name of the enterprise"`
	Domain string `json:"domain,omitempty" description:"The enterprise domain"`
}

// nolint:lll
type Context struct {
	UserAgent string   `json:"ua,omitempty" description:"The user agent used for the action"`
	IPAddress string   `json:"ip_address,omitempty" description:"The ip address the action was performed from"`
	Location  Location `json:"location" description:"The location that the actor took the action on the entity."`
}

// nolint:lll
type Location struct {
	Type   string `json:"type" validate:"required" description:"The location type. It will always be either a Workspace or an Enterprise"`
	ID     string `json:"id" validate:"required" description:"The location id"`
	Domain string `json:"domain,omitempty" description:"The location domain"`
	Name   string `json:"name,omitempty" description:"The location name"`
}

type AuditParser struct{}

var _ parsers.LogParser = AuditParser{}

func (AuditParser) LogType() string {
	return TypeAuditLogs
}
func (AuditParser) New() parsers.LogParser {
	return &AuditParser{}
}
func (AuditParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := AuditLog{}
	if err := jsoniter.UnmarshalFromString(log, &event); err != nil {
		return nil, err
	}
	event.updatePantherLog(&event.PantherLog)
	if err := parsers.Validator.Struct(&event); err != nil {
		return nil, err
	}
	return event.Logs(), nil
}

func (event *AuditLog) updatePantherLog(p *parsers.PantherLog) {
	p.SetCoreFields(TypeAuditLogs, (*timestamp.RFC3339)(&event.DateCreate), event)
	if addr := event.Context.IPAddress; addr != "" {
		p.AppendAnyIPAddress(addr)
	}
}
