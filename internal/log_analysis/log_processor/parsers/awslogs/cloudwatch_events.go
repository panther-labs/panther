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
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/extract"
)

// nolint:lll
type CloudWatchEvent struct {
	ID         *string              `json:"id" validate:"required" description:"A unique value is generated for every event. This can be helpful in tracing events as they move through rules to targets, and are processed."`
	Account    *string              `json:"account" validate:"required" description:"The 12-digit number identifying an AWS account."`
	Source     *string              `json:"source" validate:"required" description:"Identifies the service that sourced the event. All events sourced from within AWS begin with 'aws'. Customer-generated events can have any value here, as long as it doesn't begin with 'aws'. We recommend the use of Java package-name style reverse domain-name strings."`
	Resources  []string             `json:"resources" validate:"required" description:"This JSON array contains ARNs that identify resources that are involved in the event. Inclusion of these ARNs is at the discretion of the service. For example, Amazon EC2 instance state-changes include Amazon EC2 instance ARNs, Auto Scaling events include ARNs for both instances and Auto Scaling groups, but API calls with AWS CloudTrail do not include resource ARNs."`
	Region     *string              `json:"region" validate:"required" description:"Identifies the AWS region where the event originated."`
	DetailType *string              `json:"detail-type" validate:"required" description:"Identifies, in combination with the source field, the fields and values that appear in the detail field."`
	Version    *string              `json:"version" validate:"required" description:"By default, this is set to 0 (zero) in all events."`
	Time       *timestamp.RFC3339   `json:"time" validate:"required" description:"The event timestamp, which can be specified by the service originating the event. If the event spans a time interval, the service might choose to report the start time, so this value can be noticeably before the time the event is actually received."`
	Detail     *jsoniter.RawMessage `json:"detail" validate:"required" description:"A JSON object, whose content is at the discretion of the service originating the event. The detail content in the example above is very simple, just two fields. AWS API call events have detail objects with around 50 fields nested several levels deep."`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// CloudWatchEventParser parses AWS Cloudwatch Events
type CloudWatchEventParser struct{}

var _ parsers.LogParser = (*CloudWatchEventParser)(nil)

func (p *CloudWatchEventParser) New() parsers.LogParser {
	return &CloudWatchEventParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *CloudWatchEventParser) Parse(log string) ([]*parsers.PantherLog, error) {
	var event CloudWatchEvent
	if err := jsoniter.UnmarshalFromString(log, &event); err != nil {
		return nil, errors.Wrap(err, "failed to parse event")
	}
	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}

	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *CloudWatchEventParser) LogType() string {
	return TypeCloudWatchEvents
}

func (event *CloudWatchEvent) updatePantherFields(p *CloudWatchEventParser) {
	event.SetCoreFields(p.LogType(), event.Time, event)
	event.AppendAnyAWSAccountIdPtrs(event.Account)
	event.AppendAnyAWSARNs(event.Resources...)

	// polymorphic (unparsed) fields
	awsExtractor := NewAWSExtractor(&(event.AWSPantherLog))
	extract.Extract(event.Detail, awsExtractor)
}
