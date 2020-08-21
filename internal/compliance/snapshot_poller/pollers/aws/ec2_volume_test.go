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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestEC2DescribeVolumes(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeVolumesPages"})

	out, marker, err := describeVolumes(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestEC2DescribeVolumesError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeVolumesPages"})

	out, marker, err := describeVolumes(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestEC2DescribeSnapshots(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeSnapshotsPages"})

	out, err := describeSnapshots(mockSvc, awstest.ExampleVolumeId)
	assert.NotEmpty(t, out)
	assert.Len(t, out, 1)
	assert.NoError(t, err)
}

func TestEC2DescribeSnapshotsError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeSnapshotsPages"})

	out, err := describeSnapshots(mockSvc, awstest.ExampleVolumeId)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestEC2DescribeSnapshotAttribute(t *testing.T) {
	mockSvc := awstest.BuildMockEC2Svc([]string{"DescribeSnapshotAttribute"})

	out, err := describeSnapshotAttribute(mockSvc, awstest.ExampleSnapshotId)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
	assert.Len(t, out, 1)
}

func TestEC2DescribeSnapshotAttributeError(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcError([]string{"DescribeSnapshotAttribute"})

	out, err := describeSnapshotAttribute(mockSvc, awstest.ExampleSnapshotId)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestBuildEc2VolumeSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockEC2SvcAll()

	volumeSnapshot, err := buildEc2VolumeSnapshot(
		mockSvc,
		awstest.ExampleDescribeVolumesOutput.Volumes[0],
	)

	require.NotNil(t, volumeSnapshot)
	assert.Error(t, err)
	assert.NotNil(t, volumeSnapshot.AvailabilityZone)
	assert.NotEmpty(t, volumeSnapshot.Attachments)
}

func TestEc2VolumePoller(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2Volumes(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, resources)
	assert.NotNil(t, marker)
}

func TestEc2VolumePollerError(t *testing.T) {
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAllError()

	EC2ClientFunc = awstest.SetupMockEC2

	resources, marker, err := PollEc2Volumes(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Error(t, err)
	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
	assert.Nil(t, marker)
}
