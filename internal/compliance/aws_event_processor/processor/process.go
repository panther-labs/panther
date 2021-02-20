package processor

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
	classifiers = map[string]func(gjson.Result, *CloudTrailMetadata) []*resourceChange{
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

	// Events to ignore in the services we support
	ignoredEvents = map[string]struct{}{
		// acm
		"ExportCertificate":     {},
		"ResendValidationEmail": {},

		// appsync
		"CreateResolver":      {}, // unable to get AWS region from CloudTrail event
		"StartSchemaCreation": {},

		// cloudformation
		"DeleteChangeSet":          {},
		"DetectStackDrift":         {},
		"DetectStackResourceDrift": {},
		"DetectStackSetDrift":      {},
		"CreateStackSet":           {},
		"EstimateTemplateCost":     {},
		"ValidateTemplate":         {},

		// cloudtrail
		"LookupEvents": {},

		// cloudwatch log group
		"CancelExportTask":     {},
		"CreateExportTask":     {},
		"PutDestination":       {},
		"PutDestinationPolicy": {},
		"PutLogEvents":         {},
		"PutResourcePolicy":    {},
		"StartQuery":           {},
		"StopQuery":            {},
		"TestMetricFilter":     {},
		"CreateLogStream":      {},
		"FilterLogEvents":      {},

		// cognito
		"ConfirmForgotPassword": {},
		"ConfirmDevice":         {}, // This API call does not log a userIdentity with an accountID
		"ForgotPassword":        {},
		"UpdateUserAttributes":  {},

		// config
		"BatchGetResourceConfig":          {},
		"SelectResourceConfig":            {},
		"PutAggregationAuthorization":     {},
		"PutConfigurationAggregator":      {},
		"PutDeliveryChannel":              {},
		"PutEvaluations":                  {},
		"PutRemediationConfigurations":    {},
		"PutRetentionConfiguration":       {},
		"StartRemediationExecution":       {},
		"TagResource":                     {},
		"UntagResource":                   {},
		"DeleteDeliveryChannel":           {},
		"DeleteEvaluationResults":         {},
		"DeletePendingAggregationRequest": {},
		"DeleteRemediationConfiguration":  {},
		"DeleteRetentionConfiguration":    {},
		"DeliverConfigSnapshot":           {},
		"DeleteAggregationAuthorization":  {},
		"DeleteConfigRule":                {},
		"DeleteConfigurationAggregator":   {},
		"PutConfigRule":                   {},

		// dynamo
		"BatchGetItem":       {},
		"ConditionCheckItem": {},
		"DeleteBackup":       {},
		"DeleteItem":         {},
		"PutItem":            {},
		"Query":              {},
		"Scan":               {},
		"UpdateItem":         {},
		"BatchWriteItem":     {},

		// ec2
		"DeleteNetworkInterface":      {}, // we handle "DetachNetworkInterface"
		"CreateInternetGateway":       {}, // Currently we don't have an EC2 InternetGateway resource,
		"DeleteInternetGateway":       {}, // when we do we will need to handle these
		"SharedSnapshotCopyInitiated": {},
		"SharedSnapshotVolumeCreated": {},

		// ecs
		"DeleteAccountSetting":     {},
		"DeregisterTaskDefinition": {},
		"PutAccountSetting":        {},
		"PutAccountSettingDefault": {},
		"RegisterTaskDefinition":   {},
		"UpdateContainerAgent":     {},

		// elbv2
		"DeleteTargetGroup":           {},
		"CreateTargetGroup":           {},
		"ModifyTargetGroup":           {},
		"ModifyTargetGroupAttributes": {},
		"RegisterTargets":             {},
		"DeregisterTargets":           {},

		// These are elb classic events that we don't support but can't differentiate from elbv2
		// events
		"RegisterInstancesWithLoadBalancer": {},
		"ConfigureHealthCheck":              {},
		"SetLoadBalancerPoliciesOfListener": {},
		"CreateLoadBalancerPolicy":          {},

		// guardduty
		"ArchiveFindings":             {},
		"CreateIPSet":                 {},
		"CreatePublishingDestination": {},
		"CreateSampleFindings":        {},
		"CreateThreatIntelSet":        {},
		"DeclineInvitations":          {},
		"DeleteFilter":                {},
		"DeleteIPSet":                 {},
		"DeleteInvitations":           {},
		"DeleteThreatIntelSet":        {},
		"InviteMembers":               {},
		"UnarchiveFindings":           {},
		"UpdateFilter":                {},
		"UpdateFindingsFeedback":      {},
		"UpdateIPSet":                 {},
		"UpdateThreatIntelSet":        {},
		"CreateFilter":                {},

		// iam
		"ChangePassword":                 {},
		"ResetServiceSpecificCredential": {},
		"GenerateCredentialReport":       {},
		"CreateVirtualMFADevice":         {}, // MFA device creation/deletion is not related to
		"DeleteVirtualMFADevice":         {}, // users. See (Enable/Disable)MFADevice for that.
		"CreateInstanceProfile":          {},

		// kms
		"CreateGrant":                     {},
		"Decrypt":                         {},
		"Encrypt":                         {},
		"GenerateDataKey":                 {},
		"GenerateDataKeyWithoutPlaintext": {},
		"ReEncrypt":                       {},
		"RetireGrant":                     {},

		// lambda
		"AddLayerVersionPermission": {},
		"Invoke":                    {},
		"InvokeAsync":               {},
		"InvokeFunction":            {},
		"InvokeExecution":           {},

		// rds
		// TODO get suffixes
		"CreateDBClusterEndpoint":          {},
		"DeleteDBClusterEndpoint":          {},
		"CreateDBSecurityGroup":            {},
		"DeleteDBSecurityGroup":            {},
		"AuthorizeDBSecurityGroupIngress":  {},
		"DeleteDBSubnetGroup":              {},
		"DownloadDBLogFilePortion":         {},
		"ModifyCurrentDBClusterCapacity":   {},
		"ModifyDBClusterEndpoint":          {},
		"ModifyDBClusterSnapshotAttribute": {},
		"RestoreDBClusterFromS3":           {},
		"RestoreDBClusterFromSnapshot":     {},
		"RestoreDBClusterToPointInTime":    {},
		"RevokeDBSecurityGroupIngress":     {},
		"StartActivityStream":              {},
		"StopActivityStream":               {},

		// redshift
		"AcceptReservedNodeExchange":        {},
		"CreateClusterSecurityGroup":        {},
		"CreateHsmClientCertificate":        {},
		"CreateHsmConfiguration":            {},
		"DeleteClusterParameterGroup":       {},
		"DeleteClusterSecurityGroup":        {},
		"DeleteClusterSubnetGroup":          {},
		"DeleteEventSubscription":           {},
		"DeleteHsmClientCertificate":        {},
		"DeleteHsmConfiguration":            {},
		"DeleteSnapshotCopyGrant":           {},
		"DeleteSnapshotSchedule":            {},
		"ModifyClusterParameterGroup":       {},
		"ModifyClusterSubnetGroup":          {},
		"ResetClusterParameterGroup":        {},
		"RevokeClusterSecurityGroupIngress": {},
		"CreateClusterParameterGroup":       {},

		// s3
		"AbortMultipartUpload":       {},
		"CompleteMultipartUpload":    {},
		"CopyObject":                 {},
		"CreateMultipartUpload":      {},
		"DeleteObject":               {},
		"DeleteObjects":              {},
		"DeleteObjectTagging":        {},
		"HeadBucket":                 {},
		"HeadObject":                 {},
		"PutObject":                  {},
		"PutObjectAcl":               {},
		"PutObjectLegalHold":         {},
		"PutObjectLockConfiguration": {},
		"PutObjectRetention":         {},
		"PutObjectTagging":           {},
		"RestoreObject":              {},
		"SelectObjectContent":        {},
		"UploadPart":                 {},
		"UploadPartCopy":             {},

		// waf, waf-regional
		// TODO get suffixes
		"DeletePermissionPolicy": {},
		"PutPermissionPolicy":    {},

		// No accountID
		"SetUserMFAPreference":   {},
		"InitiateAuth":           {},
		"RespondToAuthChallenge": {},
	}

	// Some prefixes are common to so many API calls (and new ones are so constantly being added) that we do a prefix
	// check to save developer time from having to maintain an even more massive list
	ignoredPrefixes = []string{
		// general
		"Get",
		"Describe",
		"List",
		"AssumeRole", // covers AssumeRole, AssumeRoleWithSAML and other AssumeRole* cases
	}
)

// CloudTrailMetaData is a data struct that contains re-used fields of CloudTrail logs so that we don't have to keep
// extracting the same information
type CloudTrailMetadata struct {
	region      string
	accountID   string
	eventSource string
	eventName   string
}

// preprocessCloudTrailLog extracts some meta data that is used repeatedly for a CloudTrail log
//
// Returning nil, error means that we were unable to extract the information we need, although it should be present.
// Returning nil, nil means that we were unable to extract the information we need, but that it was not a failure on
// our part the information is simply not present.
func preprocessCloudTrailLog(detail gjson.Result) (*CloudTrailMetadata, error) {
	eventName := detail.Get("eventName")
	if !eventName.Exists() {
		return nil, errors.Errorf("unable to extract CloudTrail eventName field for eventSource '%s'",
			detail.Get("eventSource").Str) // best effort to add context
	}

	// If this is an ignored event, immediately halt processing
	if isIgnoredEvent(eventName.Str) {
		zap.L().Debug("ignoring read only event",
			zap.String("eventSource", detail.Get("eventSource").Str), // best effort to add context
			zap.String("eventName", eventName.Str))
		return nil, nil
	}

	eventSource := detail.Get("eventSource")
	if !eventSource.Exists() {
		return nil, errors.Errorf("unable to extract CloudTrail eventSource field for eventName %s",
			eventName.Str)
	}

	// Check if the service is supported
	if _, ok := classifiers[eventSource.Str]; !ok {
		zap.L().Debug("ignoring event from unsupported source",
			zap.String("eventSource", eventSource.Str),
			zap.String("eventName", eventName.Str))
		return nil, nil
	}

	accountID := detail.Get("userIdentity.accountId")
	if !accountID.Exists() {
		return nil, errors.Errorf("unable to extract CloudTrail accountId field for %s event %s",
			eventSource.Str, eventName.Str)
	}
	region := detail.Get("awsRegion")
	if !region.Exists() {
		return nil, errors.Errorf("unable to extract CloudTrail awsRegion field for %s event %s from account %s",
			eventSource.Str, eventName.Str, accountID.Str)
	}

	return &CloudTrailMetadata{
		region:      region.Str,
		accountID:   accountID.Str,
		eventSource: eventSource.Str,
		eventName:   eventName.Str,
	}, nil
}

// isIgnoredEvent determines whether or not an event can safely be ignored. Events can be ignored for many reasons,
// most common of which is either being a read only event or being an event that effects resources we don't scan
//
// NOTE: we ignore the "detail.readOnly" field because it is not always present or accurate
func isIgnoredEvent(eventName string) bool {
	_, ok := ignoredEvents[eventName]
	return ok || hasIgnoredPrefix(eventName)
}

func hasIgnoredPrefix(eventName string) bool {
	for _, prefix := range ignoredPrefixes {
		if strings.HasPrefix(eventName, prefix) {
			return true
		}
	}
	return false
}

// processCloudTrailLog determines what resources, if any, need to be scanned as a result of a given CloudTrail log
func processCloudTrailLog(detail gjson.Result, metadata *CloudTrailMetadata, changes map[string]*resourceChange) error {
	// Check if this log is from a supported account
	integration, ok := accounts[metadata.accountID]
	if !ok {
		zap.L().Debug("dropping event from unregistered account",
			zap.String("eventSource", metadata.eventSource),
			zap.String("eventName", metadata.eventName),
			zap.String("accountID", metadata.accountID))
		return nil
	}

	// Determine the AWS service the modified resource belongs to
	classifier := classifiers[metadata.eventSource]

	// Drop failed events, as they do not result in a resource change
	if errorCode := detail.Get("errorCode").Str; errorCode != "" {
		zap.L().Debug("dropping failed event",
			zap.String("eventSource", metadata.eventSource),
			zap.String("eventName", metadata.eventName),
			zap.String("errorCode", errorCode))
		return nil
	}

	// Process the body
	newChanges := classifier(detail, metadata)
	eventTime := detail.Get("eventTime").Str
	if len(newChanges) > 0 {
		readOnly := detail.Get("readOnly")
		if readOnly.Exists() && readOnly.Bool() {
			zap.L().Debug(
				"processing newChanges from event marked readOnly",
				zap.String("eventSource", metadata.eventSource),
				zap.String("eventName", metadata.eventName),
			)
		}
	}

	// One event could require multiple scans (e.g. a new VPC peering connection between two VPCs)
	for _, change := range newChanges {
		change.EventTime = eventTime
		change.IntegrationID = integration.IntegrationID
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
