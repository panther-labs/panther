// Package sysloglogs provides parsers for syslog messages.
package sysloglogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	TypeRFC5424 = "Syslog.RFC5424"
	TypeRFC3164 = "Syslog.RFC3164"
)

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("Syslog",
	logtypes.Config{
		Name:         TypeRFC3164,
		Description:  `Syslog parser for the RFC3164 format (ie. BSD-syslog messages)`,
		ReferenceURL: `https://tools.ietf.org/html/rfc3164`,
		Schema:       RFC3164{},
		NewParser:    parsers.AdapterFactory(&RFC5424Parser{}),
	},
	logtypes.Config{
		Name:         TypeRFC5424,
		Description:  `Syslog parser for the RFC5424 format.`,
		ReferenceURL: `https://tools.ietf.org/html/rfc5424`,
		Schema:       RFC5424{},
		NewParser:    parsers.AdapterFactory(&RFC5424Parser{}),
	},
)
