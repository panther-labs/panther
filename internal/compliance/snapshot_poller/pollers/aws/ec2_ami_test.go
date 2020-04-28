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
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeImages"})
	ec2Amis = make(map[string][]*string)
	ec2Amis[defaultRegion] = []*string{awstest.ExampleAmi.ImageId}

	out, err := describeImages(mockSvc, defaultRegion)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestEC2DescribeImagesError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeImages"})

	out, err := describeImages(mockSvc, defaultRegion)
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestEC2BuildAmiSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcAll()

	ec2Snapshot := buildEc2AmiSnapshot(
		mockSvc,
		awstest.ExampleAmi,
	)

	assert.Equal(t, ec2Snapshot.ID, aws.String("ari-abc234"))
	assert.Equal(t, ec2Snapshot.ImageType, aws.String("ramdisk"))
}

func TestEC2PollAmis(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, err := PollEc2Amis(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resources)
}

func TestEC2PollAmiError(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAllError()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, err := PollEc2Amis(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.Error(t, err)
	assert.Empty(t, resources)
}
