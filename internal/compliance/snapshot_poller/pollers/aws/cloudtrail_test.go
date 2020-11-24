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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

func TestCloudTrailDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvc([]string{"DescribeTrails"})

	out, err := describeTrails(mockSvc)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudTrailDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvcError([]string{"DescribeTrails"})

	out, err := describeTrails(mockSvc)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestCloudTrailGetTrailStatus(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvc([]string{"GetTrailStatus"})

	out, err := getTrailStatus(mockSvc, awstest.ExampleTrail.TrailARN)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudTrailGetTrailStatusError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvcError([]string{"GetTrailStatus"})

	out, err := getTrailStatus(mockSvc, awstest.ExampleTrail.TrailARN)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestCloudTrailGetEventSelectors(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvc([]string{"GetEventSelectors"})

	out, err := getEventSelectors(mockSvc, awstest.ExampleTrail.TrailARN)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudTrailGetEventSelectorsError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvcError([]string{"GetEventSelectors"})

	out, err := getEventSelectors(mockSvc, awstest.ExampleTrail.TrailARN)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestCloudTrailListTags(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvc([]string{"ListTags"})

	out, err := listTagsCloudTrail(mockSvc, awstest.ExampleTrail.TrailARN)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudTrailListTagsError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvcError([]string{"ListTags"})

	out, err := listTagsCloudTrail(mockSvc, awstest.ExampleTrail.TrailARN)
	require.NotNil(t, err)
	assert.Nil(t, out)
}
func TestCloudTrailBuild(t *testing.T) {
	t.Run("S3Poll", TestS3BucketPoller)
	t.Run("CloudTrailBuild", testCloudTrailBuild)
}

func testCloudTrailBuild(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvcAll()

	expected := awsmodels.CloudTrails{
		"arn:aws:cloudtrail:us-west-2:123456789012:trail/Trail": &awsmodels.CloudTrail{
			GenericResource: awsmodels.GenericResource{
				ResourceID:   awstest.ExampleTrail.TrailARN,
				ResourceType: aws.String(awsmodels.CloudTrailSchema),
			},
			GenericAWSResource: awsmodels.GenericAWSResource{
				Name: awstest.ExampleTrail.Name,
				ARN:  awstest.ExampleTrail.TrailARN,
				Tags: utils.ParseTagSlice(awstest.ExampleListTagsCloudTrail.ResourceTagList[0].TagsList),
			},
			CloudWatchLogsRoleArn:      awstest.ExampleTrail.CloudWatchLogsRoleArn,
			CloudWatchLogsLogGroupArn:  awstest.ExampleTrail.CloudWatchLogsLogGroupArn,
			HasCustomEventSelectors:    awstest.ExampleTrail.HasCustomEventSelectors,
			HomeRegion:                 awstest.ExampleTrail.HomeRegion,
			IncludeGlobalServiceEvents: awstest.ExampleTrail.IncludeGlobalServiceEvents,
			IsMultiRegionTrail:         awstest.ExampleTrail.IsMultiRegionTrail,
			IsOrganizationTrail:        awstest.ExampleTrail.IsOrganizationTrail,
			KmsKeyId:                   awstest.ExampleTrail.KmsKeyId,
			LogFileValidationEnabled:   awstest.ExampleTrail.LogFileValidationEnabled,
			S3BucketName:               awstest.ExampleTrail.S3BucketName,
			S3KeyPrefix:                awstest.ExampleTrail.S3KeyPrefix,
			SnsTopicName:               awstest.ExampleTrail.SnsTopicName, //nolint:staticcheck
			SnsTopicARN:                awstest.ExampleTrail.SnsTopicARN,
			Status:                     awstest.ExampleTrailStatus,
			EventSelectors:             awstest.ExampleTrailEventSelectors,
		},
	}

	trails, err := buildCloudTrails(mockSvc, awstest.ExampleTrail.HomeRegion)
	assert.NoError(t, err)
	assert.Equal(t, expected, trails)
}

func TestCloudTrailBuildEmpty(t *testing.T) {
	mockSvc := &awstest.MockCloudTrail{}
	mockSvc.
		On("DescribeTrails", mock.Anything).
		Return(&cloudtrail.DescribeTrailsOutput{}, nil)

	trails, err := buildCloudTrails(mockSvc, awstest.ExampleTrail.HomeRegion)
	assert.NoError(t, err)
	assert.Empty(t, trails)
}

func TestCloudTrailBuildError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudTrailSvcError([]string{"DescribeTrails"})

	trails, err := buildCloudTrails(mockSvc, awstest.ExampleTrail.HomeRegion)
	assert.Error(t, err)
	assert.Empty(t, trails)
}

func GetServiceRegionsTest(_ *awsmodels.ResourcePollerInput, _ string) (regions []*string, err error) {
	return []*string{aws.String("us-west-2")}, nil
}

func TestCloudTrailPoller(t *testing.T) {
	awstest.MockCloudTrailForSetup = awstest.BuildMockCloudTrailSvcAll()

	CloudTrailClientFunc = awstest.SetupMockCloudTrail
	GetServiceRegionsFunc = GetServiceRegionsTest

	resources, marker, err := PollCloudTrails(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.NotEmpty(t, resources)

	assert.IsType(t, &awsmodels.CloudTrail{}, resources[0].Attributes)
	assert.Equal(t, *awstest.ExampleTrail.TrailARN, resources[0].ID)

	assert.IsType(t, &awsmodels.CloudTrailMeta{}, resources[len(resources)-1].Attributes)
	assert.Equal(t, "123456789012::AWS.CloudTrail.Meta", resources[len(resources)-1].ID)
	assert.Len(t, resources[len(resources)-1].Attributes.(*awsmodels.CloudTrailMeta).Trails, 1)
}

func TestCloudTrailPollerError(t *testing.T) {
	resetCache()
	awstest.MockCloudTrailForSetup = awstest.BuildMockCloudTrailSvcError([]string{"DescribeTrails"})

	CloudTrailClientFunc = awstest.SetupMockCloudTrail

	resources, marker, err := PollCloudTrails(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.Error(t, err)
	assert.Nil(t, marker)
	assert.Len(t, resources, 0)
}

func TestCloudTrailPollerPartialError(t *testing.T) {
	resetCache()
	mockCloudTrailSvc := awstest.BuildMockCloudTrailSvc([]string{
		"DescribeTrails",
		"GetTrailStatus",
		"ListTags",
	})
	// Error here
	mockCloudTrailSvc.
		On("GetEventSelectors", mock.Anything).
		Return(
			&cloudtrail.GetEventSelectorsOutput{},
			errors.New("fake CloudTrail.GetEventSelectors error"),
		)
	awstest.MockCloudTrailForSetup = mockCloudTrailSvc

	CloudTrailClientFunc = awstest.SetupMockCloudTrail
	S3ClientFunc = awstest.SetupMockS3

	resources, marker, err := PollCloudTrails(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Error(t, err)
	assert.Nil(t, resources)
	assert.Nil(t, marker)
}

func TestCloudTrailPollerEmpty(t *testing.T) {
	resetCache()
	mockCloudTrailSvc := &awstest.MockCloudTrail{}
	mockCloudTrailSvc.
		On("DescribeTrails", mock.Anything).
		Return(&cloudtrail.DescribeTrailsOutput{}, nil)
	awstest.MockCloudTrailForSetup = mockCloudTrailSvc

	CloudTrailClientFunc = awstest.SetupMockCloudTrail

	resources, marker, err := PollCloudTrails(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	require.Len(t, resources, 1)
	assert.Nil(t, marker)
	assert.Len(t, resources[0].Attributes.(*awsmodels.CloudTrailMeta).Trails, 0)
}
