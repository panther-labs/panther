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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

// Unit Tests

func TestEC2DescribeImages(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeImages", "DescribeInstancesPages"})

	out, marker, err := describeImages(mockSvc, awstest.ExampleRegion)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestEC2DescribeImagesError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeImages", "DescribeInstancesPages"})

	out, marker, err := describeImages(mockSvc, awstest.ExampleRegion)
	assert.Error(t, err)
	assert.Nil(t, marker)
	assert.Nil(t, out)
}

func TestEC2BuildAmiSnapshot(t *testing.T) {
	ec2Snapshot := buildEc2AmiSnapshot(awstest.ExampleAmi)

	assert.Equal(t, ec2Snapshot.ID, aws.String("ari-abc234"))
	assert.Equal(t, ec2Snapshot.ImageType, aws.String("ramdisk"))
}

func TestEC2PollAmis(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2Amis(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.NotEmpty(t, resources)
}

func TestEC2PollAmiError(t *testing.T) {
	resetCache()
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAllError()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2Amis(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.Error(t, err)
	assert.Nil(t, marker)
	assert.Empty(t, resources)
}
