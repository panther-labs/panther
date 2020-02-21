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
var (
	classifiers = map[string]func(gjson.Result, string) []*resourceChange{
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

	// These events may have blank/empty userIdentity fields, so we cannot process them.
	// Luckily, we can just skip them since they are all related to authentication and so won't be changing resources.
	eventsWithoutAccountID = map[string]struct{}{
		"SetUserMFAPreference":   {},
		"GetUser":                {},
		"InitiateAuth":           {},
		"RespondToAuthChallenge": {},
		"AssumeRole":             {},
	}
)

// CloudTrailMetaData is a data struct that contains re-used fields of CloudTrail logs so that we don't have to keep
// extracting the same information
type CloudTrailMetadata struct {
	Region    string
	AccountID string
	eventName string
}

// preprocessCloudTrailLog extracts some meta data that is used repeatedly for a CloudTrail log
//
// Returning an error means that we were unable to extract the information we need, although it should be present.
// Returning nil, nil means that we were unable to extract the information we need, but that it was not a failure on
// our part the information is simply not present.
func preprocessCloudTrailLog(detail gjson.Result) (*CloudTrailMetadata, error) {
	eventName := detail.Get("eventName")
	if !eventName.Exists() {
		return nil, errors.New("unable to extract CloudTrail eventName field")
	}
	accountID := detail.Get("userIdentity.accountId")
	if !accountID.Exists() {
		// These events simply do not contain an accountId for us, return nothing
		if _, ok := eventsWithoutAccountID[eventName.Str]; ok {
			return nil, nil
		}
		return nil, errors.New("unable to extract CloudTrail accountId field")
	}
	region := detail.Get("awsRegion")
	if !region.Exists() {
		return nil, errors.New("unable to extract CloudTrail awsRegion field")
	}

	return &CloudTrailMetadata{
		Region:    region.Str,
		AccountID: accountID.Str,
		eventName: eventName.Str,
	}, nil
}

// processCloudTrailLog determines what resources, if any, need to be scanned as a result of a given CloudTrail log
func processCloudTrailLog(detail gjson.Result, metadata *CloudTrailMetadata, changes map[string]*resourceChange) error {
	// Check if this log is from a supported account
	integration, ok := accounts[metadata.AccountID]
	if !ok {
		return errors.New("dropping event from unauthorized account " + metadata.AccountID)
	}

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

	// Process the body
	newChanges := classifier(detail, metadata.AccountID)
	eventTime := detail.Get("eventTime").Str
	if len(newChanges) > 0 {
		readOnly := detail.Get("readOnly")
		if readOnly.Exists() && readOnly.Bool() {
			zap.L().Warn(
				"processing newChanges from event marked readOnly",
				zap.String("eventName", metadata.eventName),
			)
		}
	}

	// One event could require multiple scans (e.g. a new VPC peering connection between two VPCs)
	for _, change := range newChanges {
		change.EventTime = eventTime
		change.IntegrationID = *integration.IntegrationID
		zap.L().Info("resource scan required", zap.Any("changeDetail", change))
		// Prevents the following from being de-duped mistakenly:
		//
		// Resources with the same ID in different regions (different regions)
		// Service scans in the same region (different resource types)
		// Resources with the same type in the same region (different resource IDs)
		key := change.ResourceID + change.ResourceType + change.Region
		if entry, ok := changes[key]; !ok || change.EventTime > entry.EventTime {
			changes[key] = change // the newest event for this resource we've seen so far
		}
	}

	return nil
}
