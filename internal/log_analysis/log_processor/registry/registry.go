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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/fluentdsyslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/gitlablogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/nginxlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osquerylogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osseclogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/suricatalogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/sysloglogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/zeeklogs"
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
		(&awslogs.CloudTrailParser{}).LogType(): DefaultLogParser(&awslogs.CloudTrailParser{},
			&awslogs.CloudTrail{}, awslogs.CloudTrailDesc),
		(&awslogs.S3ServerAccessParser{}).LogType(): DefaultLogParser(&awslogs.S3ServerAccessParser{},
			&awslogs.S3ServerAccess{}, awslogs.S3ServerAccessDesc),
		(&awslogs.VPCFlowParser{}).LogType(): DefaultLogParser(&awslogs.VPCFlowParser{},
			&awslogs.VPCFlow{}, awslogs.VPCFlowDesc),
		(&awslogs.ALBParser{}).LogType(): DefaultLogParser(&awslogs.ALBParser{},
			&awslogs.ALB{}, awslogs.ALBDesc),
		(&awslogs.AuroraMySQLAuditParser{}).LogType(): DefaultLogParser(&awslogs.AuroraMySQLAuditParser{},
			&awslogs.AuroraMySQLAudit{}, awslogs.AuroraMySQLAuditDesc),
		(&awslogs.GuardDutyParser{}).LogType(): DefaultLogParser(&awslogs.GuardDutyParser{},
			&awslogs.GuardDuty{}, awslogs.GuardDutyDesc),
		(&nginxlogs.AccessParser{}).LogType(): DefaultLogParser(&nginxlogs.AccessParser{},
			&nginxlogs.Access{}, nginxlogs.AccessDesc),
		(&osquerylogs.DifferentialParser{}).LogType(): DefaultLogParser(&osquerylogs.DifferentialParser{},
			&osquerylogs.Differential{}, osquerylogs.DifferentialDesc),
		(&osquerylogs.BatchParser{}).LogType(): DefaultLogParser(&osquerylogs.BatchParser{},
			&osquerylogs.Batch{}, osquerylogs.BatchDesc),
		(&osquerylogs.StatusParser{}).LogType(): DefaultLogParser(&osquerylogs.StatusParser{},
			&osquerylogs.Status{}, osquerylogs.StatusDesc),
		(&osquerylogs.SnapshotParser{}).LogType(): DefaultLogParser(&osquerylogs.SnapshotParser{},
			&osquerylogs.Snapshot{}, osquerylogs.SnapshotDesc),
		(&osseclogs.EventInfoParser{}).LogType(): DefaultLogParser(&osseclogs.EventInfoParser{},
			&osseclogs.EventInfo{}, osseclogs.EventInfoDesc),
		(&sysloglogs.RFC3164Parser{}).LogType(): DefaultLogParser(&sysloglogs.RFC3164Parser{},
			&sysloglogs.RFC3164{}, sysloglogs.RFC3164Desc),
		(&sysloglogs.RFC5424Parser{}).LogType(): DefaultLogParser(&sysloglogs.RFC5424Parser{},
			&sysloglogs.RFC5424{}, sysloglogs.RFC5424Desc),
		(&fluentdsyslogs.RFC3164Parser{}).LogType(): DefaultLogParser(&fluentdsyslogs.RFC3164Parser{},
			&fluentdsyslogs.RFC3164{}, fluentdsyslogs.RFC3164Desc),
		(&fluentdsyslogs.RFC5424Parser{}).LogType(): DefaultLogParser(&fluentdsyslogs.RFC5424Parser{},
			&fluentdsyslogs.RFC5424{}, fluentdsyslogs.RFC5424Desc),
		(&zeeklogs.ZeekDNSParser{}).LogType(): DefaultLogParser(&zeeklogs.ZeekDNSParser{},
			&zeeklogs.ZeekDNS{}, zeeklogs.ZeekDNSDesc),
		(&suricatalogs.AnomalyParser{}).LogType(): DefaultLogParser(&suricatalogs.AnomalyParser{},
			&suricatalogs.Anomaly{}, suricatalogs.AnomalyDesc),
		(&gitlablogs.APIParser{}).LogType(): DefaultLogParser(&gitlablogs.APIParser{},
			&gitlablogs.API{}, gitlablogs.APIDesc),
		(&gitlablogs.RailsParser{}).LogType(): DefaultLogParser(&gitlablogs.RailsParser{},
			&gitlablogs.Rails{}, gitlablogs.RailsDesc),
		(&gitlablogs.IntegrationsParser{}).LogType(): DefaultLogParser(&gitlablogs.IntegrationsParser{},
			&gitlablogs.Integrations{}, gitlablogs.IntegrationsDesc),
		(&gitlablogs.GitParser{}).LogType(): DefaultLogParser(&gitlablogs.GitParser{},
			&gitlablogs.Git{}, gitlablogs.GitDesc),
		(&gitlablogs.AuditParser{}).LogType(): DefaultLogParser(&gitlablogs.AuditParser{},
			&gitlablogs.Audit{}, gitlablogs.AuditDesc),
		(&gitlablogs.ExceptionsParser{}).LogType(): DefaultLogParser(&gitlablogs.ExceptionsParser{},
			&gitlablogs.Exceptions{}, gitlablogs.ExceptionsDesc),
		(&awslogs.CloudTrailInsightParser{}).LogType(): DefaultLogParser(&awslogs.CloudTrailInsightParser{},
			&awslogs.CloudTrailInsight{}, awslogs.CloudTrailInsightDesc),
		(&suricatalogs.DNSParser{}).LogType(): DefaultLogParser(&suricatalogs.DNSParser{},
			&suricatalogs.DNS{}, suricatalogs.DNSDesc),
	}
)

type Registry map[string]*LogParserMetadata

// Most parsers follow this structure, these are currently assumed to all be JSON based, using LogType() as tableName
func DefaultLogParser(p parsers.LogParser, eventStruct interface{}, description string) *LogParserMetadata {
	// describes Glue table over processed data in S3
	gm := awsglue.NewGlueTableMetadata(models.LogData, p.LogType(), description, awsglue.GlueTableHourly, eventStruct)
	return &LogParserMetadata{
		Parser:            p,
		GlueTableMetadata: gm,
	}
}

// Describes each parser
type LogParserMetadata struct {
	Parser            parsers.LogParser          // does the work
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
