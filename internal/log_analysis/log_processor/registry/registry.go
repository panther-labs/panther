package registry

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
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"

	// Register log types in init() blocks
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/apachelogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/fluentdsyslogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/gitlablogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/nginxlogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osquerylogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osseclogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/suricatalogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/sysloglogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/zeeklogs"
)

func Default() *parsers.Registry {
	return parsers.DefaultRegistry()
}
func Lookup(name string) parsers.LogTypeEntry {
	return parsers.DefaultRegistry().MustGet(name)
}

func AvailableLogTypes() []string {
	return parsers.DefaultRegistry().LogTypes()
}

// Return a slice containing just the Glue tables
func AvailableTables() (tables []*awsglue.GlueTableMetadata) {
	reg := parsers.DefaultRegistry()
	for _, logType := range AvailableLogTypes() {
		if et := reg.Get(logType); et != nil {
			tables = append(tables, et.GlueTableMeta())
		}
	}
	return
}

// Available parsers returns log parsers for all available log types with nil parameters.
func AvailableParsers() map[string]pantherlog.LogParser {
	logTypes := AvailableLogTypes()
	params := make(map[string]interface{}, len(logTypes))
	for _, logType := range logTypes {
		params[logType] = nil
	}
	return parsers.DefaultRegistry().Parsers(params)
}
