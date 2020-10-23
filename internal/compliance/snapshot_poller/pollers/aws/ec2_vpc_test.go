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
	"regexp"
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestEC2DescribeVpcs(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeVpcsPages"})

	out, marker, err := describeVpcs(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestEc2VpcListIterator(t *testing.T) {
	var vpcs []*ec2.Vpc
	var marker *string

	cont := ec2VpcIterator(awstest.ExampleDescribeVpcsOutput, &vpcs, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, vpcs, 1)

	for i := 1; i < 50; i++ {
		cont = ec2VpcIterator(awstest.ExampleDescribeVpcsOutputContinue, &vpcs, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, vpcs, 1+i*2)
	}

	cont = ec2VpcIterator(awstest.ExampleDescribeVpcsOutputContinue, &vpcs, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, vpcs, 101)
}

func TestEC2DescribeVpcsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeVpcsPages"})

	out, marker, err := describeVpcs(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestEC2DescribeStaleSecurityGroups(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeStaleSecurityGroupsPages"})

	out, err := describeStaleSecurityGroups(mockSvc, awstest.ExampleVpcId)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestEC2DescribeStaleSecurityGroupsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeStaleSecurityGroupsPages"})

	out, err := describeStaleSecurityGroups(mockSvc, awstest.ExampleVpcId)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestEC2DescribeRouteTables(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeRouteTablesPages"})

	out, err := describeRouteTables(mockSvc, awstest.ExampleVpcId)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestEC2DescribeRouteTablesError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeRouteTablesPages"})

	out, err := describeRouteTables(mockSvc, awstest.ExampleVpcId)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestEC2DescribeFlowLogs(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeFlowLogsPages"})

	out, err := describeFlowLogs(mockSvc, awstest.ExampleVpcId)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestEC2DescribeFlowLogsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeFlowLogsPages"})

	out, err := describeFlowLogs(mockSvc, awstest.ExampleVpcId)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestEC2BuildVpcSnapshotPartialError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{
		"DescribeVpcsPages",
		"DescribeRouteTablesPages",
		"DescribeFlowLogsPages",
		"DescribeStaleSecurityGroupsPages",
		"DescribeSecurityGroups",
		"DescribeNetworkAcls",
	})
	mockSvc.
		On("DescribeSecurityGroupsPages", mock.Anything).
		Return(errors.New("fake describe security group error"))
	mockSvc.
		On("DescribeNetworkAclsPages", mock.Anything).
		Return(errors.New("fake describe network ACLs error"))

	ec2Snapshot, err := buildEc2VpcSnapshot(mockSvc, awstest.ExampleVpc)
	assert.Error(t, err)
	assert.Nil(t, ec2Snapshot)
}

func TestEC2BuildVpcSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcAll()
	ec2Snapshot, err := buildEc2VpcSnapshot(mockSvc, awstest.ExampleVpc)
	assert.NoError(t, err)
	assert.Len(t, ec2Snapshot.SecurityGroups, 1)
	require.NotEmpty(t, ec2Snapshot.NetworkAcls)
	assert.Len(t, ec2Snapshot.NetworkAcls, 1)
	assert.NotEmpty(t, ec2Snapshot.RouteTables)
	assert.NotEmpty(t, ec2Snapshot.FlowLogs)
	assert.NotNil(t, ec2Snapshot.DefaultNetworkAclId)
	assert.NotNil(t, ec2Snapshot.DefaultSecurityGroupId)
}

func TestEC2PollVpcs(t *testing.T) {
	resetCache()
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2Vpcs(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Regexp(
		t,
		regexp.MustCompile(`arn:aws:ec2:.*:123456789012:vpc/vpc-6aa60b12`),
		resources[0].ID,
	)
	assert.NotEmpty(t, resources)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestEC2PollVpcsError(t *testing.T) {
	resetCache()
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAllError()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2Vpcs(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Empty(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}
