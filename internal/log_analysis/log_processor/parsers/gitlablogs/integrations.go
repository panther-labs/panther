package gitlablogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// TypeIntegrations is the log type of GitLabIntegrations
const TypeIntegrations = PantherPrefix + ".Integrations"

// IntegrationsDesc describes the GitLabIntegrations log record
var IntegrationsDesc = `GitLab log with information about integrations activities such as Jira, Asana, and Irker services.
Reference: https://docs.gitlab.com/ee/administration/logs.html#integrations_jsonlog`

// Integrations is a a GitLab log line from an integrated gitlab activity
type Integrations struct {
	Severity     *string            `json:"severity" validate:"required" description:"The log level"`
	Time         *timestamp.RFC3339 `json:"time" validate:"required" description:"The event timestamp"`
	ServiceClass *string            `json:"service_class" validate:"required" description:"The class name of the integrated service"`
	ProjectID    *int64             `json:"project_id" validate:"required" description:"The project id the integration was running on"`
	ProjectPath  *string            `json:"project_path" validate:"required" description:"The project path the integration was running on"`
	Message      *string            `json:"message" validate:"required" description:"The log message from the service"`
	ClientURL    *string            `json:"client_url" validate:"required" description:"The client url of the service"`
	Error        *string            `json:"error,omitempty" description:"The error name if an error has occurred"`

	parsers.PantherLog
}

// IntegrationsParser parses gitlab integration logs
type IntegrationsParser struct{}

var _ parsers.LogParser = (*IntegrationsParser)(nil)

// New creates a new parser
func (p *IntegrationsParser) New() parsers.LogParser {
	return &IntegrationsParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *IntegrationsParser) Parse(log string) ([]*parsers.PantherLog, error) {
	gitlabIntegrations := Integrations{}

	err := jsoniter.UnmarshalFromString(log, &gitlabIntegrations)
	if err != nil {
		return nil, err
	}

	gitlabIntegrations.updatePantherFields(p)

	if err := parsers.Validator.Struct(gitlabIntegrations); err != nil {
		return nil, err
	}

	return gitlabIntegrations.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *IntegrationsParser) LogType() string {
	return TypeIntegrations
}

func (event *Integrations) updatePantherFields(p *IntegrationsParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
}
