package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import "github.com/aws/aws-sdk-go/service/cloudtrail"

const (
	CloudTrailSchema     = "AWS.CloudTrail"
	CloudTrailMetaSchema = "AWS.CloudTrail.Meta"
)

// CloudTrail contains all information about a configured CloudTrail.
//
// This includes the trail info, status, event selectors, and attributes of the logging S3 bucket.
type CloudTrail struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from cloudtrail.Trail
	CloudWatchLogsLogGroupArn  *string
	CloudWatchLogsRoleArn      *string
	HasCustomEventSelectors    *bool
	HomeRegion                 *string
	IncludeGlobalServiceEvents *bool
	IsMultiRegionTrail         *bool
	IsOrganizationTrail        *bool
	KmsKeyId                   *string
	LogFileValidationEnabled   *bool
	S3BucketName               *string
	S3KeyPrefix                *string
	SnsTopicARN                *string
	SnsTopicName               *string // Deprecated by AWS

	// Additional fields
	EventSelectors []*cloudtrail.EventSelector
	Status         *cloudtrail.GetTrailStatusOutput
}

type CloudTrailMeta struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Additional fields
	Trails               []*string
	GlobalEventSelectors []*cloudtrail.EventSelector
}

// CloudTrails are a mapping of all Trails in an account keyed by ARN.
type CloudTrails map[string]*CloudTrail
