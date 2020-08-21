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

	"github.com/stretchr/testify/assert"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestEC2DescribeNetworkAcls(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeNetworkAclsPages"})

	out, marker, err := describeNetworkAcls(mockSvc, nil)
	assert.NoError(t, err)
	assert.Nil(t, marker)
	assert.NotEmpty(t, out)
}

func TestEC2DescribeNetworkAclsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeNetworkAclsPages"})

	out, marker, err := describeNetworkAcls(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestEC2PollNetworkAcls(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2NetworkAcls(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NoError(t, err)
	assert.Nil(t, marker)
	assert.Regexp(
		t,
		regexp.MustCompile(`arn:aws:ec2:.*:123456789012:network-acl/acl-111222333`),
		resources[0].ID,
	)
	assert.NotEmpty(t, resources)
}

func TestEC2PollNetworkAclsError(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAllError()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2NetworkAcls(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NoError(t, err)
	assert.Nil(t, marker)
	assert.Empty(t, resources)
}
