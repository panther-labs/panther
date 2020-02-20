package processor

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
	"strings"

	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

// CloudWatch events which require downstream processing are summarized with this struct.
type resourceChange struct {
	AwsAccountID  string `json:"awsAccountId"`  // the 12-digit AWS account ID which owns the resource
	Delay         int64  `json:"delay"`         // How long in seconds to delay this message in SQS
	Delete        bool   `json:"delete"`        // True if the resource should be marked deleted (otherwise, update)
	EventName     string `json:"eventName"`     // CloudTrail event name (for logging only)
	EventTime     string `json:"eventTime"`     // official CloudTrail RFC3339 timestamp
	IntegrationID string `json:"integrationId"` // account integration ID
	Region        string `json:"region"`        // Region (for resource type scans only)
	ResourceID    string `json:"resourceId"`    // e.g. "arn:aws:s3:::my-bucket"
	ResourceType  string `json:"resourceType"`  // e.g. "AWS.S3.Bucket"
}

// Map each event source to the appropriate classifier function.
//
// The "classifier" takes a cloudtrail log and summarizes the required change.
// integrationID does not need to be set by the individual classifiers.
var classifiers = map[string]func(gjson.Result, string) []*resourceChange{
	"acm.amazonaws.com":                  classifyACM,
	"cloudformation.amazonaws.com":       classifyCloudFormation,
	"cloudtrail.amazonaws.com":           classifyCloudTrail,
	"config.amazonaws.com":               classifyConfig,
	"dynamodb.amazonaws.com":             classifyDynamoDB,
	"ec2.amazonaws.com":                  classifyEC2,
	"ecs.amazonaws.com":                  classifyECS,
	"elasticloadbalancing.amazonaws.com": classifyELBV2,
	"guardduty.amazonaws.com":            classifyGuardDuty,
	"iam.amazonaws.com":                  classifyIAM,
	"kms.amazonaws.com":                  classifyKMS,
	"lambda.amazonaws.com":               classifyLambda,
	"logs.amazonaws.com":                 classifyCloudWatchLogGroup,
	"rds.amazonaws.com":                  classifyRDS,
	"redshift.amazonaws.com":             classifyRedshift,
	"s3.amazonaws.com":                   classifyS3,
	"waf.amazonaws.com":                  classifyWAF,
	"waf-regional.amazonaws.com":         classifyWAFRegional,
}

// Classify the event as an update or delete operation, or drop it altogether.
func classifyCloudTrailLog(detail gjson.Result) []*resourceChange {
	// Determine the AWS service the modified resource belongs to
	source := detail.Get("eventSource").Str
	classifier, ok := classifiers[source]
	if !ok {
		zap.L().Debug("dropping event from unsupported source", zap.String("eventSource", source))
		return nil
	}

	// Drop failed events, as they do not result in a resource change
	if errorCode := detail.Get("errorCode").Str; errorCode != "" {
		zap.L().Debug("dropping failed event",
			zap.String("eventSource", source),
			zap.String("errorCode", errorCode))
		return nil
	}

	// Ignore the most common read only events
	//
	// NOTE: we ignore the "detail.readOnly" field because it is inaccurate
	eventName := detail.Get("eventName").Str
	if strings.HasPrefix(eventName, "Get") ||
		strings.HasPrefix(eventName, "BatchGet") ||
		strings.HasPrefix(eventName, "Describe") ||
		strings.HasPrefix(eventName, "List") ||
		strings.HasPrefix(eventName, "Decrypt") {

		zap.L().Debug(source+": ignoring read-only event", zap.String("eventName", eventName))
		return nil
	}

	// Check if this log is from a supported account
	accountID := detail.Get("recipientAccountId").Str
	integration, ok := accounts[accountID]
	if !ok {
		if accountID == "" {
			zap.L().Warn("dropping event without recipientAccountId field",
				zap.String("eventName", eventName),
				zap.String("eventSource", source))
		} else {
			zap.L().Warn("dropping event from unauthorized account",
				zap.String("accountId", accountID),
				zap.String("eventSource", source))
		}
		return nil
	}

	// Process the body
	changes := classifier(detail, accountID)
	eventTime := detail.Get("eventTime").Str
	for _, change := range changes {
		change.EventTime = eventTime
		change.IntegrationID = *integration.IntegrationID
	}

	return changes
}
