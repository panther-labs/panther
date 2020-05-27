package gitlablogs

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"

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

// Package gitlablogs parses GitLab JSON logs.

// PantherPrefix is the prefix of all logs parsed by this package
const PantherPrefix = "GitLab"

var (
	LogTypeExceptions = parsers.LogType{
		Name:        TypeExceptions,
		Description: ExceptionsDesc,
		Schema:      Exceptions{},
		NewParser:   parsers.AdapterFactory(&ExceptionsParser{}),
	}
	LogTypeAPI = parsers.LogType{
		Name:        TypeAPI,
		Description: APIDesc,
		Schema:      API{},
		NewParser:   parsers.AdapterFactory(&APIParser{}),
	}
	LogTypeIntegrations = parsers.LogType{
		Name:        TypeIntegrations,
		Description: IntegrationsDesc,
		Schema:      Integrations{},
		NewParser:   parsers.AdapterFactory(&IntegrationsParser{}),
	}
	LogTypeAudit = parsers.LogType{
		Name:        TypeAudit,
		Description: AuditDesc,
		Schema:      Audit{},
		NewParser:   parsers.AdapterFactory(&AuditParser{}),
	}
	LogTypeGit = parsers.LogType{
		Name:        TypeGit,
		Description: GitDesc,
		Schema:      Git{},
		NewParser:   parsers.AdapterFactory(&GitParser{}),
	}
	LogTypeRails = parsers.LogType{
		Name:        TypeRails,
		Description: RailsDesc,
		Schema:      Rails{},
		NewParser:   parsers.AdapterFactory(&RailsParser{}),
	}
)

func init() {
	parsers.MustRegister(
		LogTypeAPI,
		LogTypeAudit,
		LogTypeExceptions,
		LogTypeGit,
		LogTypeIntegrations,
		LogTypeRails,
	)
}
