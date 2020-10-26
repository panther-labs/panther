package suricatalogs

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
	TypeDNS     = "Suricata.DNS"
	TypeAnomaly = "Suricata.Anomaly"
)

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("Suricata",
	logtypes.Config{
		Name:         TypeAnomaly,
		Description:  `Suricata parser for the Anomaly event type in the EVE JSON output.`,
		ReferenceURL: `https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html#anomaly`,
		Schema:       Anomaly{},
		NewParser:    parsers.AdapterFactory(&AnomalyParser{}),
	},
	logtypes.Config{
		Name:         TypeDNS,
		Description:  `Suricata parser for the DNS event type in the EVE JSON output.`,
		ReferenceURL: `https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html#dns`,
		Schema:       DNS{},
		NewParser:    parsers.AdapterFactory(&DNSParser{}),
	},
)
