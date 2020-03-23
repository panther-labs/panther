package awslogs

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
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/extract"
)

var GuardDutyDesc = `Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity 
and unauthorized behavior inside AWS Accounts. 
See also GuardDuty Finding Format : https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html`

// nolint:lll
type GuardDuty struct {
	SchemaVersion *string              `json:"schemaVersion" validate:"required" description:"The schema format version of this record."`
	AccountID     *string              `json:"accountId" validate:"len=12,numeric" description:"The ID of the AWS account in which the activity took place that prompted GuardDuty to generate this finding."`
	Region        *string              `json:"region" validate:"required" description:"The AWS region in which the finding was generated."`
	Partition     *string              `json:"partition" validate:"required" description:"The AWS partition in which the finding was generated."`
	ID            *string              `json:"id,omitempty" validate:"required" description:"A unique identifier for the finding."`
	Arn           *string              `json:"arn" validate:"required" description:"A unique identifier formatted as an ARN for the finding."`
	Type          *string              `json:"type" validate:"required" description:"A concise yet readable description of the potential security issue."`
	Resource      *jsoniter.RawMessage `json:"resource" validate:"required" description:"The AWS resource against which the activity took place that prompted GuardDuty to generate this finding."`
	Severity      *float32             `json:"severity" validate:"required,min=0" description:"The value of the severity can fall anywhere within the 0.1 to 8.9 range."`
	CreatedAt     *timestamp.RFC3339   `json:"createdAt" validate:"required,min=0" description:"The initial creation time of the finding (UTC)."`
	UpdatedAt     *timestamp.RFC3339   `json:"updatedAt" validate:"required,min=0" description:"The last update time of the finding (UTC)."`
	Title         *string              `json:"title" validate:"required" description:"A short description of the finding."`
	Description   *string              `json:"description" validate:"required" description:"A long description of the finding."`
	Service       *GuardDutyService    `json:"service" validate:"required" description:"Additional information about the affected service."`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

type GuardDutyService struct {
	AdditionalInfo *jsoniter.RawMessage `json:"additionalInfo"`
	Action         *jsoniter.RawMessage `json:"action"`
	ServiceName    *string              `json:"serviceName" validate:"required"`
	DetectorID     *string              `json:"detectorId" validate:"required"`
	ResourceRole   *string              `json:"resourceRole"`
	EventFirstSeen *timestamp.RFC3339   `json:"eventFirstSeen"`
	EventLastSeen  *timestamp.RFC3339   `json:"eventLastSeen"`
	Archived       *bool                `json:"archived"`
	Count          *int                 `json:"count"`
}

// VPCFlowParser parses AWS VPC Flow Parser logs
type GuardDutyParser struct{}

func (p *GuardDutyParser) New() parsers.LogParser {
	return &GuardDutyParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *GuardDutyParser) Parse(log string) []*parsers.PantherLog {
	event := &GuardDuty{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}
	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *GuardDutyParser) LogType() string {
	return "AWS.GuardDuty"
}

func (event *GuardDuty) updatePantherFields(p *GuardDutyParser) {
	event.SetCoreFields(p.LogType(), event.UpdatedAt, event)

	// structured (parsed) fields
	event.AppendAnyAWSARNPtrs(event.Arn)
	event.AppendAnyAWSAccountIdPtrs(event.AccountID)

	// polymorphic (unparsed) fields
	awsExtractor := NewAWSExtractor(&(event.AWSPantherLog))
	extract.Extract(event.Resource, awsExtractor)
	if event.Service != nil {
		extract.Extract(event.Service.AdditionalInfo, awsExtractor)
		extract.Extract(event.Service.Action, awsExtractor)
	}
}
