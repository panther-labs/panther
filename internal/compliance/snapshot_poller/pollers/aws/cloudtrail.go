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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
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
		return nil, err // error is logged in getClient()
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

	trail := getTrail(ctClient, scanRequest.ResourceID)

	snapshot := buildCloudTrailSnapshot(ctClient, trail, aws.String(resourceARN.Region))
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	return snapshot, nil
}

// getTrail returns the specified cloudtrail
func getTrail(svc cloudtrailiface.CloudTrailAPI, trailARN *string) *cloudtrail.Trail {
	trail, err := svc.DescribeTrails(&cloudtrail.DescribeTrailsInput{
		TrailNameList: []*string{trailARN},
	})
	if err != nil {
		utils.LogAWSError("CloudTrail.DescribeTrails", err)
		return nil
	}

	if len(trail.TrailList) == 0 {
		zap.L().Warn("tried to scan non-existent resource",
			zap.String("resource", *trailARN),
			zap.String("resourceType", awsmodels.CloudTrailSchema))
		return nil
	}

	return trail.TrailList[0]
}

func describeTrails(svc cloudtrailiface.CloudTrailAPI) ([]*cloudtrail.Trail, error) {
	var in = &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)}
	var out *cloudtrail.DescribeTrailsOutput
	var err error

	if out, err = svc.DescribeTrails(in); err != nil {
		return nil, err
	}

	return out.TrailList, nil
}

func getTrailStatus(
	svc cloudtrailiface.CloudTrailAPI,
	trailARN *string,
) (*cloudtrail.GetTrailStatusOutput, error) {

	var in = &cloudtrail.GetTrailStatusInput{Name: trailARN}
	var out *cloudtrail.GetTrailStatusOutput
	var err error

	if out, err = svc.GetTrailStatus(in); err != nil {
		return nil, err
	}

	return out, nil
}

func listTagsCloudTrail(svc cloudtrailiface.CloudTrailAPI, trailArn *string) ([]*cloudtrail.Tag, error) {
	out, err := svc.ListTags(&cloudtrail.ListTagsInput{ResourceIdList: []*string{trailArn}})
	if err != nil {
		err = errors.WithMessagef(err, "ListTags failed for arn %s", *trailArn)
		utils.LogAWSError("CloudTrail.ListTags", err)
		return nil, err
	}

	// Since we are only specifying one resource, this will always return one value.
	// Could optimize here by calling list-tags for all resources in the region, then looking them up
	// on a per resource limit.
	return out.ResourceTagList[0].TagsList, nil
}

func getEventSelectors(svc cloudtrailiface.CloudTrailAPI, trailARN *string) ([]*cloudtrail.EventSelector, error) {
	out, err := svc.GetEventSelectors(&cloudtrail.GetEventSelectorsInput{TrailName: trailARN})
	if err != nil {
		return nil, err
	}
	return out.EventSelectors, nil
}

// buildCloudTrailSnapshot builds a complete CloudTrail snapshot for a given trail
func buildCloudTrailSnapshot(svc cloudtrailiface.CloudTrailAPI, trail *cloudtrail.Trail, region *string) *awsmodels.CloudTrail {
	// Return on empty requests and shadow trails (trails not from this region)
	if trail == nil || *trail.HomeRegion != *region {
		zap.L().Debug("shadow trail or nil request")
		return nil
	}
	zap.L().Debug("cloudtrail has valid arn", zap.String("arn", *trail.TrailARN))
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
		utils.LogAWSError("CloudTrail.GetTrailStatus", err)
	} else {
		cloudTrail.Status = status
	}

	eventSelectors, err := getEventSelectors(svc, trail.TrailARN)
	if err != nil {
		utils.LogAWSError("CloudTrail.GetEventSelectors", err)
	} else {
		cloudTrail.EventSelectors = eventSelectors
	}

	tags, err := listTagsCloudTrail(svc, trail.TrailARN)
	if err == nil {
		cloudTrail.Tags = utils.ParseTagSlice(tags)
	}

	return cloudTrail
}

// buildCloudTrails combines the output of each required API call to build the CloudTrailSnapshot.
//
// It returns a mapping of CloudTrailARN to CloudTrailSnapshot.
func buildCloudTrails(
	cloudtrailSvc cloudtrailiface.CloudTrailAPI, region *string,
) awsmodels.CloudTrails {

	cloudTrails := make(awsmodels.CloudTrails)

	zap.L().Debug("describing CloudTrails")
	trails, err := describeTrails(cloudtrailSvc)
	if err != nil {
		utils.LogAWSError("CloudTrail.Describe", err)
		// Return early since there are no CloudTrails
		return cloudTrails
	}

	// Build each CloudTrail's snapshot by requesting additional context from CloudTrail/S3 APIs
	for _, trail := range trails {
		cloudTrail := buildCloudTrailSnapshot(cloudtrailSvc, trail, region)
		// Skip same account shadow trails
		if cloudTrail == nil {
			continue
		}
		cloudTrails[*trail.TrailARN] = cloudTrail
	}

	return cloudTrails
}

// PollCloudTrails gathers information on all CloudTrails in an AWS account.
func PollCloudTrails(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting CloudTrail resource poller")
	cloudTrailSnapshots := make(awsmodels.CloudTrails)

	// TODO CloudTrail scans must always scan all regions, fix this
	for _, regionID := range utils.GetServiceRegions([]*string{pollerInput.Region}, "cloudtrail") {
		zap.L().Debug("building CloudTrail snapshots", zap.String("region", *regionID))
		cloudTrailSvc, err := getCloudTrailClient(pollerInput, *regionID)
		if err != nil {
			continue // error is logged in getClient()
		}

		// Build the list of all CloudTrails for the given region
		regionTrails := buildCloudTrails(cloudTrailSvc, regionID)

		// Insert each trail into the master list of CloudTrails (if it is not there already)
		for trailARN, trail := range regionTrails {
			trail.Region = regionID
			trail.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			if _, ok := cloudTrailSnapshots[trailARN]; ok {
				zap.L().Info(
					"overwriting existing CloudTrail snapshot", zap.String("resourceId", trailARN),
				)
			}
			cloudTrailSnapshots[trailARN] = trail
		}
	}

	zap.L().Debug("finished polling CloudTrail", zap.Int("count", len(cloudTrailSnapshots)))

	metaResourceID := utils.GenerateResourceID(
		pollerInput.AuthSourceParsedARN.AccountID,
		"",
		awsmodels.CloudTrailMetaSchema,
	)

	// Handle the case where there are no CloudTrails to return
	if len(cloudTrailSnapshots) == 0 {
		return []*apimodels.AddResourceEntry{{
			Attributes: &awsmodels.CloudTrailMeta{
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
			},
			ID:              apimodels.ResourceID(metaResourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.CloudTrailMetaSchema,
		}}, nil
	}

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
	}

	// Append each individual trail to  the results and update the meta resource appropriately
	resources := make([]*apimodels.AddResourceEntry, 0, len(cloudTrailSnapshots)+1)
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
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      trail,
			ID:              apimodels.ResourceID(*trail.ARN),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.CloudTrailSchema,
		})
	}

	// Append the meta resource to the results
	resources = append(resources, &apimodels.AddResourceEntry{
		Attributes:      accountSnapshot,
		ID:              apimodels.ResourceID(metaResourceID),
		IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
		IntegrationType: apimodels.IntegrationTypeAws,
		Type:            awsmodels.CloudTrailMetaSchema,
	})

	return resources, nil
}
