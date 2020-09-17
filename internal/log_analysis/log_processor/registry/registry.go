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
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"

	// Register log types in init() blocks
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/apachelogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/fastlylogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/fluentdsyslogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/gitlablogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/gravitationallogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/juniperlogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/laceworklogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/nginxlogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osquerylogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osseclogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/suricatalogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/sysloglogs"
	_ "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/zeeklogs"
)

// Default returns the default log type registry
func Default() *logtypes.Registry {
	return logtypes.DefaultRegistry()
}

// Lookup finds a log type entry or panics
// Panics if the name is not registered
func Lookup(name string) logtypes.Entry {
	return logtypes.DefaultRegistry().MustGet(name)
}

// AvailableLogTypes returns all available log types in the default registry
func AvailableLogTypes() []string {
	return logtypes.DefaultRegistry().LogTypes()
}

// AvailableTables returns a slice containing the Glue tables for all available log types
func AvailableTables() (tables []*awsglue.GlueTableMetadata) {
	entries := logtypes.DefaultRegistry().Entries()
	tables = make([]*awsglue.GlueTableMetadata, len(entries))
	for i, entry := range entries {
		tables[i] = entry.GlueTableMeta()
	}
	return
}

// Available parsers returns log parsers for all available log types with nil parameters.
// Panics if a parser factory in the default registry fails with nil params.
func AvailableParsers() map[string]parsers.Interface {
	entries := logtypes.DefaultRegistry().Entries()
	available := make(map[string]parsers.Interface, len(entries))
	for _, entry := range entries {
		logType := entry.Describe().Name
		parser, err := entry.NewParser(nil)
		if err != nil {
			panic(errors.Errorf("failed to create %q parser with nil params", logType))
		}
		available[logType] = parser
	}
	return available
}
