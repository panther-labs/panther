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
	"regexp"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestEC2DescribeSecurityGroups(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeSecurityGroupsPages"})

	out, marker, err := describeSecurityGroups(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestEc2SecurityGroupListIterator(t *testing.T) {
	var groups []*ec2.SecurityGroup
	var marker *string

	cont := ec2SecurityGroupIterator(awstest.ExampleDescribeSecurityGroupsOutput, &groups, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, groups, 1)

	for i := 1; i < 50; i++ {
		cont = ec2SecurityGroupIterator(awstest.ExampleDescribeSecurityGroupsOutputContinue, &groups, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, groups, 1+i*2)
	}

	cont = ec2SecurityGroupIterator(awstest.ExampleDescribeSecurityGroupsOutputContinue, &groups, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, groups, 101)
}

func TestEC2DescribeSecurityGroupsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeSecurityGroupsPages"})

	out, marker, err := describeSecurityGroups(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestEC2PollSecurityGroups(t *testing.T) {
	resetCache()
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	AssumeRoleFunc = awstest.AssumeRoleMock
	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2SecurityGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Regexp(
		t,
		regexp.MustCompile(`arn:aws:ec2:.*:123456789012:security-group/sg-111222333`),
		resources[0].ID,
	)
	assert.NotEmpty(t, resources)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestEC2PollSecurityGroupsError(t *testing.T) {
	resetCache()
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAllError()

	AssumeRoleFunc = awstest.AssumeRoleMock
	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2SecurityGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Empty(t, resources)
	assert.Nil(t, marker)
	require.Error(t, err)
}
