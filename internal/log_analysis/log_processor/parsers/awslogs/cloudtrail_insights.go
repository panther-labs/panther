package awslogs

import (
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

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

var CloudTrailInsightDesc = `AWSCloudTrailInsight represents the content of a CloudTrail Insight event record S3 object.
Log format & samples can be seen here: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html`

// nolint:lll
type CloudTrailInsightRecords struct {
	Records []*CloudTrailInsight `json:"Records" validate:"required,dive"`
}

// Reference from https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
// nolint:lll
type CloudTrailInsight struct {
	EventVersion       *string            `json:"eventVersion" validate:"required" description:"The version of the log event format."`
	EventTime          *timestamp.RFC3339 `json:"eventTime" validate:"required" description:"The date and time the request was made, in coordinated universal time (UTC)."`
	AWSRegion          *string            `json:"awsRegion" validate:"required" description:"The AWS region that the request was made to, such as us-east-2."`
	EventID            *string            `json:"eventId" validate:"required" description:"GUID generated by CloudTrail to uniquely identify each event. You can use this value to identify a single event. For example, you can use the ID as a primary key to retrieve log data from a searchable database."`
	EventType          *string            `json:"eventType" validate:"required,eq=AwsCloudTrailInsight" description:"Identifies the type of event that generated the event record. This can be the one of the following values: AwsApiCall, AwsServiceEvent, AwsConsoleSignIn"`
	RecipientAccountID *string            `json:"recipientAccountId,omitempty" validate:"omitempty,len=12,numeric" description:"Represents the account ID that received this event. The recipientAccountID may be different from the CloudTrail userIdentity Element accountId. This can occur in cross-account resource access."`
	SharedEventID      *string            `json:"sharedEventId" validate:"required" description:"A GUID that is generated by CloudTrail Insights to uniquely identify an Insights event. sharedEventID is common between the start and the end Insights events."`
	InsightDetails     *InsightDetails    `json:"insightDetails" validate:"required" description:" Shows information about the underlying triggers of an Insights event, such as event source, statistics, API name, and whether the event is the start or end of the Insights event."`
	EventCategory      *string            `json:"eventCategory" validate:"required,eq=Insight" description:"Shows the event category that is used in LookupEvents calls. In Insights events, the value is insight."`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// nolint:lll
type InsightDetails struct {
	State          *string         `json:"state" validate:"required" description:" Shows whether the event represents the start or end of the insight (the start or end of unusual activity). Values are Start or End."`
	EventSource    *string         `json:"eventSource" validate:"required" description:"The AWS API for which unusual activity was detected."`
	EventName      *string         `json:"eventName" validate:"required" description:"The AWS API for which unusual activity was detected."`
	InsightType    *string         `json:"insightType" validate:"required" description:"The type of Insights event. Value is ApiCallRateInsight. "`
	InsightContext *InsightContext `json:"insightContext,omitempty" description:"Data about the rate of calls that triggered the Insights event compared to the normal rate of calls to the subject API per minute. "`
}

// nolint:lll
type InsightContext struct {
	Statistics *InsightStatistics `json:"statistics,omitempty" description:"A container for data about the typical average rate of calls to the subject API by an account, the rate of calls that triggered the Insights event, and the duration, in minutes, of the Insights event."`
}

// nolint:lll
type InsightStatistics struct {
	Baseline        *InsightAverage `json:"baseline,omitempty" description:"Shows the typical average rate of calls to the subject API by an account within a specific AWS Region."`
	Insight         *InsightAverage `json:"insight,omitempty" description:"Shows the unusual rate of calls to the subject API that triggers the logging of an Insights event."`
	InsightDuration *float32        `json:"insightDuration,omitempty" description:"The duration, in minutes, of an Insights event (the time period from the start to the end of unusual activity on the subject API). insightDuration only occurs in end Insights events."`
}

// nolint:lll
type InsightAverage struct {
	Average *float64 `json:"average,omitempty" description:"Average value for the insight metric"`
}

type CloudTrailInsightParser struct{}

// NOTE: guard to ensure interface implementation
var _ parsers.LogParser = (*CloudTrailInsightParser)(nil)

func (p *CloudTrailInsightParser) New() parsers.LogParser {
	return &CloudTrailInsightParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *CloudTrailInsightParser) Parse(log string) ([]*parsers.PantherLog, error) {
	cloudTrailInsightRecords := &CloudTrailInsightRecords{}
	err := jsoniter.UnmarshalFromString(log, cloudTrailInsightRecords)
	if err != nil {
		return nil, err
	}

	for _, event := range cloudTrailInsightRecords.Records {
		event.updatePantherFields(p)
	}

	if err := parsers.Validator.Struct(cloudTrailInsightRecords); err != nil {
		return nil, err
	}
	result := make([]*parsers.PantherLog, len(cloudTrailInsightRecords.Records))
	for i, event := range cloudTrailInsightRecords.Records {
		result[i] = event.Log()
	}
	return result, nil
}

// LogType returns the log type supported by this parser
func (p *CloudTrailInsightParser) LogType() string {
	return "AWS.CloudTrailInsight"
}

func (event *CloudTrailInsight) updatePantherFields(p *CloudTrailInsightParser) {
	event.SetCoreFields(p.LogType(), event.EventTime, event)

	event.AppendAnyAWSAccountIdPtrs(event.RecipientAccountID)
}
