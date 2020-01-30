package registry

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/nginx"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osquerylogs"
	"github.com/panther-labs/panther/pkg/awsglue"
)

type Interface interface {
	Elements() map[string]*LogParserMetadata
	LookupParser(logType string) (lpm *LogParserMetadata)
}

// Don't forget to register new parsers!
var (
	// mapping of LogType -> LogParserMetadata
	parsersRegistry = Registry{
		(&awslogs.CloudTrailParser{}).LogType(): DefaultHourlyLogParser(&awslogs.CloudTrailParser{},
			&awslogs.CloudTrail{}, awslogs.CloudTrailDesc),
		(&awslogs.S3ServerAccessParser{}).LogType(): DefaultHourlyLogParser(&awslogs.S3ServerAccessParser{},
			&awslogs.S3ServerAccess{}, awslogs.S3ServerAccessDesc),
		(&awslogs.VPCFlowParser{}).LogType(): DefaultHourlyLogParser(&awslogs.VPCFlowParser{},
			&awslogs.VPCFlow{}, awslogs.VPCFlowDesc),
		(&awslogs.ALBParser{}).LogType(): DefaultHourlyLogParser(&awslogs.ALBParser{},
			&awslogs.ALB{}, awslogs.ALBDesc),
		(&awslogs.AuroraMySQLAuditParser{}).LogType(): DefaultHourlyLogParser(&awslogs.AuroraMySQLAuditParser{},
			&awslogs.AuroraMySQLAudit{}, awslogs.AuroraMySQLAuditDesc),
		(&awslogs.GuardDutyParser{}).LogType(): DefaultHourlyLogParser(&awslogs.GuardDutyParser{},
			&awslogs.GuardDuty{}, awslogs.GuardDutyDesc),
		(&nginx.AccessParser{}).LogType(): DefaultHourlyLogParser(&nginx.AccessParser{},
			&nginx.Access{}, nginx.AccessDesc),
		(&osquerylogs.DifferentialParser{}).LogType(): DefaultHourlyLogParser(&osquerylogs.DifferentialParser{},
			&osquerylogs.Differential{}, osquerylogs.DifferentialDesc),
		(&osquerylogs.BatchParser{}).LogType(): DefaultHourlyLogParser(&osquerylogs.BatchParser{},
			&osquerylogs.Batch{}, osquerylogs.BatchDesc),
		(&osquerylogs.StatusParser{}).LogType(): DefaultHourlyLogParser(&osquerylogs.StatusParser{},
			&osquerylogs.Status{}, osquerylogs.StatusDesc),
		(&osquerylogs.SnapshotParser{}).LogType(): DefaultHourlyLogParser(&osquerylogs.SnapshotParser{},
			&osquerylogs.Snapshot{}, osquerylogs.SnapshotDesc),
	}
)

type Registry map[string]*LogParserMetadata

// Most parsers follow this structure, these are currently assumed to all be JSON based, using LogType() as tableName
func DefaultHourlyLogParser(p parsers.LogParser, eventStruct interface{}, description string) *LogParserMetadata {
	tableName := p.LogType() // default to LogType()

	// describes Glue table over processed data in S3
	gm, err := awsglue.NewGlueMetadata(awsglue.InternalDatabaseName, tableName, description, awsglue.GlueTableHourly, false, eventStruct)
	if err != nil {
		panic(err) // panic is justified because this means configuration is WRONG
	}

	return &LogParserMetadata{
		Parser:      p,
		EventStruct: eventStruct,
		Description: description,
		Glue:        gm,
	}
}

// Describes each parser
type LogParserMetadata struct {
	Parser      parsers.LogParser     // does the work
	EventStruct interface{}           // should be a struct that defines a log event
	Description string                // describes the  data for documentation and will be added into Glue table
	Glue        *awsglue.GlueMetadata // describes associated AWS Glue table (used to generate CF)
}

// Return a map containing all the available parsers
func AvailableParsers() Registry {
	return parsersRegistry
}

// Return a slice containing just the Glue tables
func AvailableTables() (tables []*awsglue.GlueMetadata) {
	for _, lpm := range parsersRegistry {
		tables = append(tables, lpm.Glue)
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
