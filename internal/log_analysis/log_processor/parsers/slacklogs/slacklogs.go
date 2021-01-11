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

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"

func LogTypes() logtypes.Group {
	return logTypes
}

// We use an immediately called function to register the time decoder before building the logtype entries.
var logTypes = func() logtypes.Group {
	return logtypes.Must("Slack",
		logtypes.ConfigJSON{
			Name: TypeAuditLogs,
			// nolint:lll
			Description:  "Slack audit logs provide a view of the actions users perform in an Enterprise Grid organization.",
			ReferenceURL: "https://api.slack.com/enterprise/audit-logs",
			NewEvent: func() interface{} {
				return &AuditLog{}
			},
		},

		logtypes.ConfigJSON{
			Name: TypeAccessLogs,
			// nolint:lll
			Description:  "Access logs for users on a Slack workspace.",
			ReferenceURL: "https://api.slack.com/methods/team.accessLogs",
			NewEvent: func() interface{} {
				return &AccessLog{}
			},
		},

		logtypes.ConfigJSON{
			Name: TypeIntegrationLogs,
			// nolint:lll
			Description:  "Integration activity logs for a team, including when integrations are added, modified and removed.",
			ReferenceURL: "https://api.slack.com/methods/team.integrationLogs",
			NewEvent: func() interface{} {
				return &IntegrationLog{}
			},
		},
	)
}()
