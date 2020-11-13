// Package gitlablogs parses GitLab JSON logs.
package gitlablogs

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

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

const (
	// LogTypePrefix is the prefix of all logs parsed by this package and the name of the log type group
	LogTypePrefix = "GitLab"
	// TypeAPI is the type of the GitLabAPI log record
	TypeAPI = LogTypePrefix + ".API"
	// TypeAudit is the log type of Audit log records
	TypeAudit = LogTypePrefix + ".Audit"
	// TypeExceptions is the log type of Exceptions log records
	TypeExceptions = LogTypePrefix + ".Exceptions"
	// TypeGit is the log type of Git log records
	TypeGit = LogTypePrefix + ".Git"
	// TypeIntegrations is the log type of GitLabIntegrations
	TypeIntegrations = LogTypePrefix + ".Integrations"
	// TypeProduction is the type of the GitLabRails log record
	TypeProduction = LogTypePrefix + ".Production"
)

// LogTypes exports the available log type entries
func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must(LogTypePrefix,
	logtypes.Config{
		Name: TypeAPI,
		Description: `GitLab log for API requests received from GitLab.
		NOTE: We are using the latest version of GitLab API logs. Some fields differ from the official documentation`,
		ReferenceURL: `https://docs.gitlab.com/ee/administration/logs.html#api_jsonlog`,
		Schema:       API{},
		NewParser:    parsers.AdapterFactory(&APIParser{}),
	},
	logtypes.Config{
		Name:         TypeAudit,
		Description:  `GitLab log file containing changes to group or project settings`,
		ReferenceURL: `https://docs.gitlab.com/ee/administration/logs.html#audit_jsonlog`,
		Schema:       Audit{},
		NewParser:    parsers.AdapterFactory(&AuditParser{}),
	},
	logtypes.Config{
		Name:         TypeExceptions,
		Description:  `GitLab log file containing changes to group or project settings`,
		ReferenceURL: `https://docs.gitlab.com/ee/administration/logs.html#exceptions_jsonlog`,
		Schema:       Exceptions{},
		NewParser:    parsers.AdapterFactory(&ExceptionsParser{}),
	},
	logtypes.Config{
		Name:         TypeGit,
		Description:  `GitLab log file containing all failed requests from GitLab to Git repositories.`,
		ReferenceURL: `https://docs.gitlab.com/ee/administration/logs.html#git_jsonlog`,
		Schema:       Git{},
		NewParser:    parsers.AdapterFactory(&GitParser{}),
	},
	logtypes.Config{
		Name:         TypeIntegrations,
		Description:  `GitLab log with information about integrations activities such as Jira, Asana, and Irker services.`,
		ReferenceURL: `https://docs.gitlab.com/ee/administration/logs.html#integrations_jsonlog`,
		Schema:       Integrations{},
		NewParser:    parsers.AdapterFactory(&IntegrationsParser{}),
	},
	logtypes.Config{
		Name:         TypeProduction,
		Description:  `GitLab log for Production controller requests received from GitLab`,
		ReferenceURL: `https://docs.gitlab.com/ee/administration/logs.html#production_jsonlog`,
		Schema:       Production{},
		NewParser:    parsers.AdapterFactory(&ProductionParser{}),
	},
)
