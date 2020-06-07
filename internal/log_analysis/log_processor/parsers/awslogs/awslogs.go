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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	TypeALB               = "AWS.ALB"
	TypeAuroraMySQLAudit  = `AWS.AuroraMySQLAudit`
	TypeCloudTrail        = `AWS.CloudTrail`
	TypeCloudTrailDigest  = "AWS.CloudTrailDigest"
	TypeCloudTrailInsight = "AWS.CloudTrailInsight"
	TypeGuardDuty         = "AWS.GuardDuty"
	TypeS3ServerAccess    = "AWS.S3ServerAccess"
	TypeVPCFlow           = "AWS.VPCFlow"
)

// nolint:lll
func init() {
	parsers.MustRegister(
		parsers.LogTypeConfig{
			Name:         TypeALB,
			Description:  `Application Load Balancer logs Layer 7 network logs for your application load balancer.`,
			ReferenceURL: `https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html`,
			Schema:       ALB{},
			NewParser:    parsers.AdapterFactory(&ALBParser{}),
		},
		parsers.LogTypeConfig{
			Name:         TypeAuroraMySQLAudit,
			Description:  `AuroraMySQLAudit is an RDS Aurora audit log which contains context around database calls.`,
			ReferenceURL: `https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html`,
			Schema:       AuroraMySQLAudit{},
			NewParser:    parsers.AdapterFactory(&AuroraMySQLAuditParser{}),
		},
		parsers.LogTypeConfig{
			Name:         TypeCloudTrail,
			Description:  `AWSCloudTrail represents the content of a CloudTrail S3 object.`,
			ReferenceURL: `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html`,
			Schema:       CloudTrail{},
			NewParser:    parsers.AdapterFactory(&CloudTrailParser{}),
		},
		parsers.LogTypeConfig{
			Name:         TypeCloudTrailDigest,
			Description:  `AWSCloudTrailDigest contains the names of the log files that were delivered to your Amazon S3 bucket during the last hour, the hash values for those log files, and the signature of the previous digest file.`,
			ReferenceURL: `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html`,
			Schema:       CloudTrailDigest{},
			NewParser:    parsers.AdapterFactory(&CloudTrailDigestParser{}),
		},
		parsers.LogTypeConfig{
			Name:         TypeCloudTrailInsight,
			Description:  `AWSCloudTrailInsight represents the content of a CloudTrail Insight event record S3 object.`,
			ReferenceURL: `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html`,
			Schema:       CloudTrailInsight{},
			NewParser:    parsers.AdapterFactory(&CloudTrailInsightParser{}),
		},
		parsers.LogTypeConfig{
			Name:         TypeGuardDuty,
			Description:  `Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior inside AWS Accounts.`,
			ReferenceURL: `https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html`,
			Schema:       GuardDuty{},
			NewParser:    parsers.AdapterFactory(&GuardDutyParser{}),
		},
		parsers.LogTypeConfig{
			Name:         TypeS3ServerAccess,
			Description:  `S3ServerAccess is an AWS S3 Access Log.`,
			ReferenceURL: `https://docs.aws.amazon.com/AmazonS3/latest/dev/LogFormat.html`,
			Schema:       S3ServerAccess{},
			NewParser:    parsers.AdapterFactory(&S3ServerAccessParser{}),
		},
		parsers.LogTypeConfig{
			Name:         TypeVPCFlow,
			Description:  `VPCFlow is a VPC NetFlow log, which is a layer 3 representation of network traffic in EC2.`,
			ReferenceURL: `https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html`,
			Schema:       VPCFlow{},
			NewParser:    parsers.AdapterFactory(&VPCFlowParser{}),
		},
	)
}
