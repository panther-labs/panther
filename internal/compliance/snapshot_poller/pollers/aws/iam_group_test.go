package aws

/**
 * A Cloud-Native SIEM for the Modern Security Team
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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestIamGroupList(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListGroupsPages"})

	out := listGroups(mockSvc)
	assert.NotEmpty(t, out)
}

func TestIamGroupListError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListGroupsPages"})

	out := listGroups(mockSvc)
	assert.Nil(t, out)
}

func TestIamGroupListPolicies(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListGroupPoliciesPages"})

	out := listGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.NotEmpty(t, out)
}

func TestIamGroupListPoliciesError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListGroupPoliciesPages"})

	out := listGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.Nil(t, out)
}

func TestIamGroupListAttachedPolicies(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListAttachedGroupPoliciesPages"})

	out := listAttachedGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.NotEmpty(t, out)
}

func TestIamGroupListAttachedPoliciesError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListAttachedGroupPoliciesPages"})

	out := listAttachedGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.Nil(t, out)
}

func TestIamGroupGet(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetGroup"})

	out := getGroup(mockSvc, aws.String("groupname"))
	assert.NotEmpty(t, out.Users)
}

func TestIamGroupGetError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GetGroup"})

	out := getGroup(mockSvc, aws.String("groupname"))
	assert.Nil(t, out)
}

func TestIamGroupGetPolicy(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetGroupPolicy"})

	out := getGroupPolicy(mockSvc, aws.String("groupname"), aws.String("policyname"))
	assert.NotEmpty(t, out)
}

func TestIamGroupGetPolicyError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GetGroupPolicy"})

	out := getGroupPolicy(mockSvc, aws.String("groupname"), aws.String("policyname"))
	assert.Nil(t, out)
}

func TestBuildIamGroupSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcAll()

	groupSnapshot := buildIamGroupSnapshot(
		mockSvc,
		&iam.Group{
			GroupName:  aws.String("example-group"),
			GroupId:    aws.String("123456"),
			Arn:        aws.String("arn:::::group/example-group"),
			CreateDate: awstest.ExampleDate,
		},
	)

	assert.NotEmpty(t, groupSnapshot.Users)
	assert.NotNil(t, groupSnapshot.ID)
	assert.NotNil(t, groupSnapshot.ARN)
}

func TestBuildIamGroupSnapshotError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcAllError()

	groupSnapshot := buildIamGroupSnapshot(
		mockSvc,
		&iam.Group{
			Arn:        aws.String("arn:::::group/example-group"),
			CreateDate: awstest.ExampleDate,
			GroupId:    aws.String("123456"),
			GroupName:  aws.String("example-group"),
		},
	)

	/*
		expected := &awsmodels.IamGroup{
			GenericResource: awsmodels.GenericResource{
				ResourceID:   aws.String("arn:::::group/example-group"),
				TimeCreated:  utils.DateTimeFormat(*awstest.ExampleDate),
				ResourceType: aws.String(awsmodels.IAMGroupSchema),
			},
			GenericAWSResource: awsmodels.GenericAWSResource{
				ARN:    aws.String("arn:::::group/example-group"),
				ID:     aws.String("123456"),
				Name:   aws.String("example-group"),
				Region: aws.String(awsmodels.GlobalRegion),
			},
		}

	*/
	var expected *awsmodels.IamGroup
	require.Equal(t, expected, groupSnapshot)
}

func TestIamGroupPoller(t *testing.T) {
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAll()

	IAMClientFunc = awstest.SetupMockIAM

	resources, err := PollIamGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Len(t, resources, 1)
	assert.Equal(t, *awstest.ExampleGroup.Arn, string(resources[0].ID))
}

func TestIamGroupPollerError(t *testing.T) {
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAllError()

	IAMClientFunc = awstest.SetupMockIAM

	resources, err := PollIamGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
}
