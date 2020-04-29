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
	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/pkg/awsglue"
)

// type Interface interface {
// 	Elements() map[string]*LogParserMetadata
// 	LookupParser(logType string) (lpm *LogParserMetadata)
// }

// FIXME: this is not working due to init uncertainty
// Don't forget to register new parsers with parsers.MustRegister!
func initRegistry() Registry {
	r := Registry{}
	for _, logType := range parsers.AvailableLogTypes() {
		r[logType.Name] = DefaultLogParser(logType)
	}
	return r
}

// mapping of LogType -> LogParserMetadata
var parsersRegistry = initRegistry()

type Registry map[string]*LogParserMetadata

// Most parsers follow this structure, these are currently assumed to all be JSON based, using LogType() as tableName
func DefaultLogParser(logType parsers.LogType) *LogParserMetadata {
	// describes Glue table over processed data in S3
	gm := awsglue.NewGlueTableMetadata(models.LogData, logType.Name, logType.Description, awsglue.GlueTableHourly, logType.Schema)
	return &LogParserMetadata{
		LogType:           logType.Name,
		Factory:           logType.NewParser,
		GlueTableMetadata: gm,
	}
}

// Describes each parser
type LogParserMetadata struct {
	LogType           string
	Factory           func() parsers.Parser
	GlueTableMetadata *awsglue.GlueTableMetadata // describes associated AWS Glue table (used to generate CF)
}

// Return a map containing all the available parsers
func AvailableParsers() Registry {
	return parsersRegistry
}

// Return a slice containing just the Glue tables
func AvailableTables() (tables []*awsglue.GlueTableMetadata) {
	for _, lpm := range parsersRegistry {
		tables = append(tables, lpm.GlueTableMetadata)
	}
	return
}

// Provides access to underlying type so 'range' will work
func (r Registry) Elements() map[string]*LogParserMetadata {
	return r
}

// Provides mapping from LogType -> metadata (panics!), used in core code to ensure ALL parsers are registered
func (r Registry) LookupParser(logType string) (lpm *LogParserMetadata) {
	lpm, found := r[logType]
	if !found {
		panic("Cannot find LogType: " + logType) // super serious error, die die die
	}
	return
}
