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

	"github.com/panther-labs/panther/internal/compliance/snapshotlogs"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// Generates an init() function that populates the registry with all log types exported by
// packages inside "internal/log_analysis/log_processor/parsers/..."
//go:generate go run ./generate_init.go ../parsers/...

// These will be populated by the generated init() code
var (
	nativeLogTypes    logtypes.Group
	availableLogTypes = &logtypes.Registry{}
	internalLogTypes  = logtypes.MustMerge("internal", snapshotlogs.LogTypes())
)

// NativeLogTypesResolver returns a resolver for native log types.
// Use this instead of registry.Default()
func NativeLogTypesResolver() logtypes.Resolver {
	return logtypes.LocalResolver(nativeLogTypes)
}

// InternalLogTypesResolver returns a resolver for internal log types.
// Sources for these log types are managed by panther and they should not be available to users for source onboarding
func InternalLogTypesResolver() logtypes.Resolver {
	return logtypes.LocalResolver(internalLogTypes)

}

// LogTypes exposes all available log types as a read-only group.
func LogTypes() logtypes.Group {
	return availableLogTypes
}

// Register adds a group to the registry of available log types
func Register(group logtypes.Group) error {
	return availableLogTypes.Register(group)
}

func Del(logType string) bool {
	if nativeLogTypes.Find(logType) != nil {
		panic(`tried to remove native log type`)
	}
	return availableLogTypes.Del(logType)
}

// Lookup finds a log type entry or panics
// Panics if the name is not registered
func Lookup(name string) logtypes.Entry {
	return logtypes.MustFind(LogTypes(), name)
}

// AvailableLogTypes returns all available log types in the default registry
func AvailableLogTypes() (logTypes []string) {
	for _, e := range LogTypes().Entries() {
		logTypes = append(logTypes, e.String())
	}
	return
}

// AvailableTables returns a slice containing the Glue tables for all available log types
func AvailableTables() (tables []*awsglue.GlueTableMetadata) {
	entries := LogTypes().Entries()
	tables = make([]*awsglue.GlueTableMetadata, len(entries))
	for i, entry := range entries {
		tables[i] = entry.GlueTableMeta()
	}
	return
}

// AvailableParsers returns log parsers for all native log types with nil parameters.
// Panics if a parser factory in the default registry fails with nil params.
func AvailableParsers() map[string]parsers.Interface {
	entries := LogTypes().Entries()
	available := make(map[string]parsers.Interface, len(entries))
	for _, entry := range entries {
		logType := entry.String()
		parser, err := entry.NewParser(nil)
		if err != nil {
			panic(errors.Errorf("failed to create %q parser with nil params", logType))
		}
		available[logType] = parser
	}
	return available
}
