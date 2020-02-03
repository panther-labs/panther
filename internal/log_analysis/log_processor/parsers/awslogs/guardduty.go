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

type GuardDuty struct {
	SchemaVersion *string              `json:"schemaVersion" validate:"required"`
	AccountID     *string              `json:"accountId" validate:"len=12,numeric"`
	Region        *string              `json:"region" validate:"required"`
	Partition     *string              `json:"partition" validate:"required"`
	ID            *string              `json:"id,omitempty" validate:"required"`
	Arn           *string              `json:"arn" validate:"required"`
	Type          *string              `json:"type" validate:"required"`
	Resource      *jsoniter.RawMessage `json:"resource" validate:"required"`
	Severity      *int                 `json:"severity" validate:"required,min=0"`
	CreatedAt     *timestamp.RFC3339   `json:"createdAt" validate:"required,min=0"`
	UpdatedAt     *timestamp.RFC3339   `json:"updatedAt" validate:"required,min=0"`
	Title         *string              `json:"title" validate:"required"`
	Description   *string              `json:"description" validate:"required"`
	Service       *GuardDutyService    `json:"service" validate:"required"`

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

// Parse returns the parsed events or nil if parsing failed
func (p *GuardDutyParser) Parse(log string) []interface{} {
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
	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *GuardDutyParser) LogType() string {
	return "AWS.GuardDuty"
}

func (event *GuardDuty) updatePantherFields(p *GuardDutyParser) {
	if event.UpdatedAt != nil {
		event.SetRequired(p.LogType(), *event.UpdatedAt)
	}

	// structured (parsed) fields
	if event.Arn != nil {
		event.AppendAnyAWSARNs(*event.Arn)
	}
	if event.AccountID != nil {
		event.AppendAnyAWSAccountIds(*event.AccountID)
	}

	// polymorphic (unparsed) fields
	awsExtractor := NewAWSExtractor(&(event.AWSPantherLog))
	extract.Extract(event.Resource, awsExtractor)
	if event.Service != nil {
		if event.Service.AdditionalInfo != nil {
			extract.Extract(event.Service.AdditionalInfo, awsExtractor)
		}
		if event.Service.Action != nil {
			extract.Extract(event.Service.Action, awsExtractor)
		}
	}
}
