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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/stretchr/testify/assert"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestIamGroupList(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListGroupsPages"})

	out, marker, err := listGroups(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestIamGroupListError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListGroupsPages"})

	out, marker, err := listGroups(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestIamGroupListIterator(t *testing.T) {
	var groups []*iam.Group
	var marker *string

	cont := iamGroupIterator(awstest.ExampleListGroupsOutput, &groups, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, groups, 1)

	for i := 1; i < 50; i++ {
		cont = iamGroupIterator(awstest.ExampleListGroupsOutputContinue, &groups, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, groups, 1+i*2)
	}

	cont = iamGroupIterator(awstest.ExampleListGroupsOutputContinue, &groups, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, groups, 101)
}

func TestIamGroupListPolicies(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListGroupPoliciesPages"})

	out, err := listGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestIamGroupListPoliciesError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListGroupPoliciesPages"})

	out, err := listGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestIamGroupListAttachedPolicies(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListAttachedGroupPoliciesPages"})

	out, err := listAttachedGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestIamGroupListAttachedPoliciesError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListAttachedGroupPoliciesPages"})

	out, err := listAttachedGroupPolicies(mockSvc, aws.String("ExampleGroup"))
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestIamGroupGet(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetGroup"})

	out, err := getGroup(mockSvc, aws.String("groupname"))
	assert.NoError(t, err)
	assert.NotEmpty(t, out.Users)
}

func TestIamGroupGetError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GetGroup"})

	out, err := getGroup(mockSvc, aws.String("groupname"))
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestIamGroupGetPolicy(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetGroupPolicy"})

	out, err := getGroupPolicy(mockSvc, aws.String("groupname"), aws.String("policyname"))
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestIamGroupGetPolicyError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GetGroupPolicy"})

	out, err := getGroupPolicy(mockSvc, aws.String("groupname"), aws.String("policyname"))
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestBuildIamGroupSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcAll()

	groupSnapshot, err := buildIamGroupSnapshot(
		mockSvc,
		&iam.Group{
			GroupName:  aws.String("example-group"),
			GroupId:    aws.String("123456"),
			Arn:        aws.String("arn:::::group/example-group"),
			CreateDate: &awstest.ExampleTime,
		},
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, groupSnapshot.Users)
	assert.NotNil(t, groupSnapshot.ID)
	assert.NotNil(t, groupSnapshot.ARN)
}

func TestBuildIamGroupSnapshotError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcAllError()

	groupSnapshot, err := buildIamGroupSnapshot(
		mockSvc,
		&iam.Group{
			Arn:        aws.String("arn:::::group/example-group"),
			CreateDate: &awstest.ExampleTime,
			GroupId:    aws.String("123456"),
			GroupName:  aws.String("example-group"),
		},
	)

	assert.Error(t, err)
	var expected *awsmodels.IamGroup
	assert.Equal(t, expected, groupSnapshot)
}

func TestIamGroupPoller(t *testing.T) {
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAll()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIamGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NoError(t, err)
	assert.Len(t, resources, 1)
	assert.Equal(t, *awstest.ExampleGroup.Arn, resources[0].ID)
	assert.Nil(t, marker)
}

func TestIamGroupPollerError(t *testing.T) {
	resetCache()
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAllError()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIamGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Error(t, err)
	assert.Nil(t, resources)
	assert.Nil(t, marker)
}
