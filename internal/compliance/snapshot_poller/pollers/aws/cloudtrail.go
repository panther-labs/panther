package aws

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

var (
	// CloudTrailClientFunc is the function it setup the CloudTrail client.
	CloudTrailClientFunc = setupCloudTrailClient
)

func setupCloudTrailClient(sess *session.Session, cfg *aws.Config) interface{} {
	return cloudtrail.New(sess, cfg)
}

func getCloudTrailClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (cloudtrailiface.CloudTrailAPI, error) {

	client, err := getClient(pollerResourceInput, CloudTrailClientFunc, "cloudtrail", region)
	if err != nil {
		return nil, err
	}

	return client.(cloudtrailiface.CloudTrailAPI), nil
}

// PollCloudTrailTrail polls a single CloudTrail trail resource
func PollCloudTrailTrail(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	ctClient, err := getCloudTrailClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	trail, err := getTrail(ctClient, scanRequest.ResourceID)
	if err != nil {
		return nil, err
	}

	snapshot, err := buildCloudTrailSnapshot(ctClient, trail, aws.String(resourceARN.Region))
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	return snapshot, nil
}

// getTrail returns the specified cloudtrail
func getTrail(svc cloudtrailiface.CloudTrailAPI, trailARN *string) (*cloudtrail.Trail, error) {
	trail, err := svc.DescribeTrails(&cloudtrail.DescribeTrailsInput{
		TrailNameList: []*string{trailARN},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "CloudTrail.DescribeTrails: %s", aws.StringValue(trailARN))
	}

	if len(trail.TrailList) == 0 {
		zap.L().Warn("tried to scan non-existent resource",
			zap.String("resource", *trailARN),
			zap.String("resourceType", awsmodels.CloudTrailSchema))
		return nil, nil
	}

	return trail.TrailList[0], nil
}

func describeTrails(svc cloudtrailiface.CloudTrailAPI) ([]*cloudtrail.Trail, error) {
	out, err := svc.DescribeTrails(&cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
	if err != nil {
		return nil, errors.Wrap(err, "CloudTrail.DescribeTrails")
	}

	return out.TrailList, nil
}

func getTrailStatus(svc cloudtrailiface.CloudTrailAPI, trailARN *string) (*cloudtrail.GetTrailStatusOutput, error) {
	trailStatus, err := svc.GetTrailStatus(&cloudtrail.GetTrailStatusInput{Name: trailARN})
	if err != nil {
		return nil, errors.Wrapf(err, "CloudTrail.GetTrailStatus: %s", aws.StringValue(trailARN))
	}

	return trailStatus, nil
}

func listTagsCloudTrail(svc cloudtrailiface.CloudTrailAPI, trailArn *string) ([]*cloudtrail.Tag, error) {
	out, err := svc.ListTags(&cloudtrail.ListTagsInput{ResourceIdList: []*string{trailArn}})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == cloudtrail.ErrCodeARNInvalidException {
			// At this point in the scan, we know the ARN is valid. This exception is thrown when you
			// try to make a cloudtrail:ListTags API call on a trail in another account. The only
			// trail that we would be scanning in another account is an organization trail, which we
			// are going to discard at the end of the scan anyways so it doesn't matter what we
			// return here as long as it's not an error.
			return nil, nil
		}
		return nil, errors.Wrapf(err, "CloudTrail.ListTags: %s", aws.StringValue(trailArn))
	}

	// Since we are only specifying one resource, this will always return one value.
	// Could optimize here by calling list-tags for all resources in the region, then looking them up
	// on a per resource limit.
	return out.ResourceTagList[0].TagsList, nil
}

func getEventSelectors(svc cloudtrailiface.CloudTrailAPI, trailARN *string) ([]*cloudtrail.EventSelector, error) {
	out, err := svc.GetEventSelectors(&cloudtrail.GetEventSelectorsInput{TrailName: trailARN})
	if err != nil {
		return nil, errors.Wrapf(err, "CloudTrail.GetEventSelectors: %s", aws.StringValue(trailARN))
	}
	return out.EventSelectors, nil
}

// buildCloudTrailSnapshot builds a complete CloudTrail snapshot for a given trail
func buildCloudTrailSnapshot(svc cloudtrailiface.CloudTrailAPI, trail *cloudtrail.Trail, region *string) (*awsmodels.CloudTrail, error) {
	// Return on empty requests and shadow trails (trails not from this region)
	if trail == nil || *trail.HomeRegion != *region {
		zap.L().Debug("shadow trail or nil request")
		return nil, nil
	}
	cloudTrail := &awsmodels.CloudTrail{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   trail.TrailARN,
			ResourceType: aws.String(awsmodels.CloudTrailSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  trail.TrailARN,
			Name: trail.Name,
		},
		CloudWatchLogsLogGroupArn:  trail.CloudWatchLogsLogGroupArn,
		CloudWatchLogsRoleArn:      trail.CloudWatchLogsRoleArn,
		HasCustomEventSelectors:    trail.HasCustomEventSelectors,
		HomeRegion:                 trail.HomeRegion,
		IncludeGlobalServiceEvents: trail.IncludeGlobalServiceEvents,
		IsMultiRegionTrail:         trail.IsMultiRegionTrail,
		IsOrganizationTrail:        trail.IsOrganizationTrail,
		KmsKeyId:                   trail.KmsKeyId,
		LogFileValidationEnabled:   trail.LogFileValidationEnabled,
		S3BucketName:               trail.S3BucketName,
		S3KeyPrefix:                trail.S3KeyPrefix,
		SnsTopicARN:                trail.SnsTopicARN,
		SnsTopicName:               trail.SnsTopicName, //nolint:staticcheck
	}

	status, err := getTrailStatus(svc, trail.TrailARN)
	if err != nil {
		return nil, err
	}
	cloudTrail.Status = status

	eventSelectors, err := getEventSelectors(svc, trail.TrailARN)
	if err != nil {
		return nil, err
	}
	cloudTrail.EventSelectors = eventSelectors

	tags, err := listTagsCloudTrail(svc, trail.TrailARN)
	if err != nil {
		return nil, err
	}
	cloudTrail.Tags = utils.ParseTagSlice(tags)

	return cloudTrail, nil
}

// buildCloudTrails combines the output of each required API call to build the CloudTrailSnapshot.
//
// It returns a mapping of CloudTrailARN to CloudTrailSnapshot.
func buildCloudTrails(
	cloudtrailSvc cloudtrailiface.CloudTrailAPI, region *string,
) (awsmodels.CloudTrails, error) {

	cloudTrails := make(awsmodels.CloudTrails)

	zap.L().Debug("describing CloudTrails")
	trails, err := describeTrails(cloudtrailSvc)
	if err != nil {
		return nil, errors.WithMessagef(err, "region: %s", *region)
	}

	// Build each CloudTrail's snapshot by requesting additional context from CloudTrail/S3 APIs
	for _, trail := range trails {
		cloudTrail, err := buildCloudTrailSnapshot(cloudtrailSvc, trail, region)
		if err != nil {
			return nil, err
		}
		// Skip same account shadow trails
		if cloudTrail == nil {
			continue
		}
		cloudTrails[*trail.TrailARN] = cloudTrail
	}

	return cloudTrails, nil
}

// PollCloudTrails gathers information on all CloudTrails in an AWS account.
func PollCloudTrails(pollerInput *awsmodels.ResourcePollerInput) (
	[]apimodels.AddResourceEntry, *string, error) {

	zap.L().Debug("starting CloudTrail resource poller")
	cloudTrailSnapshots := make(awsmodels.CloudTrails)
	regions, err := GetServiceRegionsFunc(pollerInput, awsmodels.CloudTrailSchema)
	if err != nil {
		return nil, nil, err
	}

	for _, regionID := range regions {
		zap.L().Debug("building CloudTrail snapshots", zap.String("region", *regionID))
		cloudTrailSvc, err := getCloudTrailClient(pollerInput, *regionID)
		if err != nil {
			var e *RegionIgnoreListError
			if errors.As(err, &e) {
				zap.L().Debug("Skipping denied region in CloudTrail scan")
				continue
			}
			return nil, nil, err
		}

		// Build the list of all CloudTrails for the given region
		regionTrails, err := buildCloudTrails(cloudTrailSvc, regionID)
		if err != nil {
			return nil, nil, err
		}

		// Insert each trail into the master list of CloudTrails (if it is not there already)
		for trailARN, trail := range regionTrails {
			trail.Region = regionID
			trail.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			cloudTrailSnapshots[trailARN] = trail
		}
	}

	metaResourceID := utils.GenerateResourceID(
		pollerInput.AuthSourceParsedARN.AccountID,
		"",
		awsmodels.CloudTrailMetaSchema,
	)

	// Build the meta resource
	accountSnapshot := &awsmodels.CloudTrailMeta{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   aws.String(metaResourceID),
			ResourceType: aws.String(awsmodels.CloudTrailMetaSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			AccountID: aws.String(pollerInput.AuthSourceParsedARN.AccountID),
			Name:      aws.String(awsmodels.CloudTrailMetaSchema),
			Region:    aws.String("global"),
		},
		Trails: []*string{},
	}

	// Append each individual trail to  the results and update the meta resource appropriately
	resources := make([]apimodels.AddResourceEntry, 0, len(cloudTrailSnapshots)+1)
	for _, trail := range cloudTrailSnapshots {
		// Update the meta resource, regardless of if we are processing an organization trail
		accountSnapshot.Trails = append(accountSnapshot.Trails, trail.ResourceID)
		if *trail.IsMultiRegionTrail && *trail.Status.IsLogging {
			accountSnapshot.GlobalEventSelectors = append(
				accountSnapshot.GlobalEventSelectors,
				trail.EventSelectors...,
			)
		}

		// Organization trails are a special case.
		// Organization trails should only show up as a resource in the master organization account, however,
		// they need to be represented in the meta resource for every account they exist in
		if *trail.IsOrganizationTrail {
			// Determine if we are in the master account (the org trail's accountID = scanned accountID)
			parsed, err := arn.Parse(*trail.ARN)
			if err != nil {
				zap.L().Error("unable to parse organization trail arn", zap.String("arn", *trail.ARN))
				continue
			}
			if parsed.AccountID != pollerInput.AuthSourceParsedARN.AccountID {
				zap.L().Info("skipping organization trail")
				continue
			}
		}

		// For non-organization trails and organization trails in the master account, add the trail to the results
		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      trail,
			ID:              *trail.ARN,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.CloudTrailSchema,
		})
	}

	// Append the meta resource to the results
	resources = append(resources, apimodels.AddResourceEntry{
		Attributes:      accountSnapshot,
		ID:              metaResourceID,
		IntegrationID:   *pollerInput.IntegrationID,
		IntegrationType: integrationType,
		Type:            awsmodels.CloudTrailMetaSchema,
	})

	// We don't support paging for CloudTrail resources. Since there is a limit of 5 trails per
	// region, we should not run into timeout issues here anyways.
	//
	// Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html
	return resources, nil, nil
}
