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

	out, err := describeVpcs(mockSvc)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestEC2DescribeVpcsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeVpcsPages"})

	out, err := describeVpcs(mockSvc)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestEC2DescribeStaleSecurityGroups(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeStaleSecurityGroupsPages"})

	out := describeStaleSecurityGroups(mockSvc, awstest.ExampleVpcId)
	assert.NotEmpty(t, out)
}

func TestEC2DescribeStaleSecurityGroupsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeStaleSecurityGroupsPages"})

	out := describeStaleSecurityGroups(mockSvc, awstest.ExampleVpcId)
	assert.Nil(t, out)
}

func TestEC2DescribeRouteTables(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeRouteTablesPages"})

	out := describeRouteTables(mockSvc, awstest.ExampleVpcId)
	assert.NotEmpty(t, out)
}

func TestEC2DescribeRouteTablesError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeRouteTablesPages"})

	out := describeRouteTables(mockSvc, awstest.ExampleVpcId)
	assert.Nil(t, out)
}

func TestEC2DescribeFlowLogs(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeFlowLogsPages"})

	out := describeFlowLogs(mockSvc, awstest.ExampleVpcId)
	assert.NotEmpty(t, out)
}

func TestEC2DescribeFlowLogsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeFlowLogsPages"})

	out := describeFlowLogs(mockSvc, awstest.ExampleVpcId)
	assert.Nil(t, out)
}

func TestEC2BuildVpcSnapshot(t *testing.T) {
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
		Return(&ec2.DescribeSecurityGroupsOutput{}, errors.New("fake describe security group error"))
	mockSvc.
		On("DescribeNetworkAclsPages", mock.Anything).
		Return(&ec2.DescribeNetworkAclsOutput{}, errors.New("fake describe network ACLs error"))

	ec2Snapshot := buildEc2VpcSnapshot(mockSvc, awstest.ExampleVpc)
	assert.Len(t, ec2Snapshot.SecurityGroups, 1)
	require.NotEmpty(t, ec2Snapshot.NetworkAcls)
	assert.Len(t, ec2Snapshot.NetworkAcls, 1)
	assert.NotEmpty(t, ec2Snapshot.RouteTables)
	assert.NotEmpty(t, ec2Snapshot.FlowLogs)
}

func TestEC2PollVpcs(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, err := PollEc2Vpcs(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Regexp(
		t,
		regexp.MustCompile(`arn:aws:ec2:.*:123456789012:vpc/vpc-6aa60b12`),
		resources[0].ID,
	)
	assert.NotEmpty(t, resources)
}

func TestEC2PollVpcsError(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAllError()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, err := PollEc2Vpcs(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.Error(t, err)
	assert.Empty(t, resources)
}
