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

	"github.com/pkg/errors"
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

// CloudTrailMetaData is a data struct that contains re-used fields of CloudTrail logs so that we don't have to keep
// extracting the same information
type CloudTrailMetaData struct {
	Region    string
	AccountID string
	eventName string
}

// generateSourceKey creates the key used for the cweAccounts cache for a given CloudTrail metadata struct
func (metadata *CloudTrailMetaData) generateSourceKey() string {
	return metadata.AccountID + "/" + metadata.Region
}

// preprocessCloudTrailLog extracts some meta data that is used repeatedly for a CloudTrail log
func preprocessCloudTrailLog(detail gjson.Result) (*CloudTrailMetaData, error) {
	accountID := detail.Get("userIdentity.accountId")
	if !accountID.Exists() {
		return nil, errors.New("unable to extract CloudTrail accountId field")
	}
	region := detail.Get("awsRegion")
	if !region.Exists() {
		return nil, errors.New("unable to extract CloudTrail awsRegion field")
	}
	eventName := detail.Get("eventName")
	if !eventName.Exists() {
		return nil, errors.New("unable to extract CloudTrail eventName field")
	}

	return &CloudTrailMetaData{
		Region:    region.Str,
		AccountID: accountID.Str,
		eventName: eventName.Str,
	}, nil
}

// processCloudTrailLog determines what resources, if any, need to be scanned as a result of a given CloudTrail log
func processCloudTrailLog(detail gjson.Result, metadata *CloudTrailMetaData) []*resourceChange {
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
	// NOTE: we ignore the "detail.readOnly" field because it is not always present or accurate
	if strings.HasPrefix(metadata.eventName, "Get") ||
		strings.HasPrefix(metadata.eventName, "BatchGet") ||
		strings.HasPrefix(metadata.eventName, "Describe") ||
		strings.HasPrefix(metadata.eventName, "Decrypt") ||
		strings.HasPrefix(metadata.eventName, "List") {

		zap.L().Debug(source+": ignoring read-only event", zap.String("eventName", metadata.eventName))
		return nil
	}

	// Check if this log is from a supported account
	integration, ok := accounts[metadata.AccountID]
	if !ok {
		zap.L().Warn("dropping event from unauthorized account",
			zap.String("accountId", metadata.AccountID),
			zap.String("eventSource", source))
		return nil
	}

	// Process the body
	changes := classifier(detail, metadata.AccountID)
	eventTime := detail.Get("eventTime").Str
	if len(changes) > 0 {
		readOnly := detail.Get("readOnly")
		if readOnly.Exists() && readOnly.Bool() {
			zap.L().Warn(
				"processing changes from event marked readOnly",
				zap.String("eventName", metadata.eventName),
			)
		}
	}

	for _, change := range changes {
		change.EventTime = eventTime
		change.IntegrationID = *integration.IntegrationID
	}

	return changes
}
