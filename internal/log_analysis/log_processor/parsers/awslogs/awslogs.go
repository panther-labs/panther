package awslogs

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

var (
	LogTypeAWSALB = parsers.LogType{
		Name:        TypeALB,
		Description: ALBDesc,
		Schema:      ALB{},
		NewParser:   parsers.AdapterFactory(&ALBParser{}),
	}
	LogTypeAuroraMySQLAudit = parsers.LogType{
		Name:        TypeAuroraMySQLAudit,
		Description: AuroraMySQLAuditDesc,
		Schema:      AuroraMySQLAudit{},
		NewParser:   parsers.AdapterFactory(&AuroraMySQLAuditParser{}),
	}
	LogTypeCloudTrail = parsers.LogType{
		Name:        TypeCloudTrail,
		Description: CloudTrailDesc,
		Schema:      CloudTrail{},
		NewParser:   parsers.AdapterFactory(&CloudTrailParser{}),
	}
)

func init() {
	// Register custom meta factory for AWS logs
	pantherlog.MustRegisterMetaPrefix("AWS", metaFactory)

	parsers.MustRegister(
		LogTypeAWSALB,
		LogTypeAuroraMySQLAudit,
		LogTypeCloudTrail,
	)
}
