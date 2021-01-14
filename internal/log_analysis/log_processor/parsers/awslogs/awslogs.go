// Package awslogs defines parsers and log types for AWS logs.
package awslogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	TypeALB               = "AWS.ALB"
	TypeAuroraMySQLAudit  = `AWS.AuroraMySQLAudit`
	TypeCloudTrail        = `AWS.CloudTrail`
	TypeCloudTrailDigest  = "AWS.CloudTrailDigest"
	TypeCloudTrailInsight = "AWS.CloudTrailInsight"
	TypeCloudWatchEvents  = "AWS.CloudWatchEvents"
	TypeGuardDuty         = "AWS.GuardDuty"
	TypeS3ServerAccess    = "AWS.S3ServerAccess"
	TypeVPCDns            = "AWS.VPCDns"
	TypeVPCFlow           = "AWS.VPCFlow"
	TypeWAFWebACL         = "AWS.WAFWebACL"
)

// LogTypes exports the available log type entries
func LogTypes() logtypes.Group {
	return logTypes
}

// nolint:lll
var logTypes = logtypes.Must("AWS",
	logtypes.Config{
		Name:         TypeALB,
		Description:  `Application Load Balancer logs Layer 7 network logs for your application load balancer.`,
		ReferenceURL: `https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html`,
		Schema:       ALB{},
		NewParser:    parsers.AdapterFactory(&ALBParser{}),
	},
	logtypes.Config{
		Name:         TypeAuroraMySQLAudit,
		Description:  `AuroraMySQLAudit is an RDS Aurora audit log which contains context around database calls.`,
		ReferenceURL: `https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html`,
		Schema:       AuroraMySQLAudit{},
		NewParser:    parsers.AdapterFactory(&AuroraMySQLAuditParser{}),
	},
	logtypes.Config{
		Name:         TypeCloudTrail,
		Description:  `AWSCloudTrail represents the content of a CloudTrail S3 object.`,
		ReferenceURL: `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html`,
		Schema:       mustBuildEventSchema(CloudTrail{}),
		NewParser:    pantherlog.FactoryFunc(newCloudTrailParser),
	},
	logtypes.ConfigJSON{
		Name:         TypeCloudTrailDigest,
		Description:  `AWSCloudTrailDigest contains the names of the log files that were delivered to your Amazon S3 bucket during the last hour, the hash values for those log files, and the signature of the previous digest file.`,
		ReferenceURL: `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html`,
		NewEvent: func() interface{} {
			return &CloudTrailDigest{}
		},
	},
	logtypes.Config{
		Name:         TypeCloudTrailInsight,
		Description:  `AWSCloudTrailInsight represents the content of a CloudTrail Insight event record S3 object.`,
		ReferenceURL: `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html`,
		Schema:       mustBuildEventSchema(CloudTrailInsight{}),
		NewParser: pantherlog.FactoryFunc(func(_ interface{}) (parsers.Interface, error) {
			return &CloudTrailInsightParser{}, nil
		}),
	},
	logtypes.Config{
		Name:         TypeCloudWatchEvents,
		Description:  `Amazon CloudWatch Events describe a change in Amazon Web Services (AWS) resources.`,
		ReferenceURL: `https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/CloudWatchEventsandEventPatterns.html`,
		Schema:       CloudWatchEvent{},
		NewParser:    parsers.AdapterFactory(&CloudWatchEventParser{}),
	},
	logtypes.Config{
		Name:         TypeGuardDuty,
		Description:  `Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior inside AWS Accounts.`,
		ReferenceURL: `https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html`,
		Schema:       GuardDuty{},
		NewParser:    parsers.AdapterFactory(&GuardDutyParser{}),
	},
	logtypes.Config{
		Name:         TypeS3ServerAccess,
		Description:  `S3ServerAccess is an AWS S3 Access Log.`,
		ReferenceURL: `https://docs.aws.amazon.com/AmazonS3/latest/dev/LogFormat.html`,
		Schema:       S3ServerAccess{},
		NewParser:    parsers.AdapterFactory(&S3ServerAccessParser{}),
	},
	logtypes.ConfigJSON{
		Name:         TypeVPCDns,
		Description:  `DNS query logs of the queries that VPC DNS resolvers forward to Route 53.`,
		ReferenceURL: `https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html`,
		NewEvent: func() interface{} {
			return &VPCDns{}
		},
		ExtraIndicators: pantherlog.FieldSet{ // these are not present in the struct but added by the extractors
			pantherlog.FieldDomainName,
		},
	},
	logtypes.Config{
		Name:         TypeVPCFlow,
		Description:  `VPCFlow is a VPC NetFlow log, which is a layer 3 representation of network traffic in EC2.`,
		ReferenceURL: `https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html`,
		Schema:       VPCFlow{},
		NewParser:    parsers.AdapterFactory(&VPCFlowParser{}),
	},
	logtypes.ConfigJSON{
		Name:         TypeWAFWebACL,
		Description:  `WAF Web ACL traffic information logs.`,
		ReferenceURL: `https://docs.aws.amazon.com/waf/latest/developerguide/logging.html`,
		NewEvent: func() interface{} {
			return &WAFWebACL{}
		},
	},
)
