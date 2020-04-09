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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestCloudFormationStackDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvc([]string{"DescribeStacksPages"})

	out, err := describeStacks(mockSvc)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudFormationStackDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvcError([]string{"DescribeStacksPages"})

	out, err := describeStacks(mockSvc)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestCloudFormationStackDetectStackDrift(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvc([]string{"DetectStackDrift"})

	out, err := detectStackDrift(mockSvc, awstest.ExampleCertificateArn)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudFormationStackDetectStackDriftError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvcError([]string{"DetectStackDrift"})

	out, err := detectStackDrift(mockSvc, awstest.ExampleCertificateArn)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestCloudFormationStackDescribeResourceDrifts(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvc([]string{"DescribeStackResourceDriftsPages"})

	out := describeStackResourceDrifts(mockSvc, awstest.ExampleCertificateArn)
	assert.NotEmpty(t, out)
}

func TestCloudFormationStackDescribeResourceDriftsError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvcError([]string{"DescribeStackResourceDriftsPages"})

	out := describeStackResourceDrifts(mockSvc, awstest.ExampleCertificateArn)
	assert.Nil(t, out)
}

func TestCloudFormationStackBuildSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvcAll()

	certSnapshot := buildCloudFormationStackSnapshot(
		mockSvc,
		awstest.ExampleDescribeStacks.Stacks[0],
	)

	assert.NotEmpty(t, certSnapshot.Parameters)
	assert.NotEmpty(t, certSnapshot.Drifts)
}

func TestCloudFormationStackBuildSnapshotError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudFormationSvcAllError()

	certSnapshot := buildCloudFormationStackSnapshot(
		mockSvc,
		awstest.ExampleDescribeStacks.Stacks[0],
	)

	assert.NotNil(t, certSnapshot.Name)
	assert.Nil(t, certSnapshot.Drifts)
}

func TestCloudFormationStackPoller(t *testing.T) {
	awstest.MockCloudFormationForSetup = awstest.BuildMockCloudFormationSvcAll()

	CloudFormationClientFunc = awstest.SetupMockCloudFormation

	resources, err := PollCloudFormationStacks(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Equal(t, *awstest.ExampleDescribeStacks.Stacks[0].StackId, string(resources[0].ID))
	assert.NotEmpty(t, resources)
}

func TestCloudFormationStackPollerError(t *testing.T) {
	awstest.MockCloudFormationForSetup = awstest.BuildMockCloudFormationSvcAllError()

	CloudFormationClientFunc = awstest.SetupMockCloudFormation

	resources, err := PollCloudFormationStacks(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.Error(t, err)
	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
}

func TestCloudFormationStackDescribeDriftDetectionStatusInProgress(t *testing.T) {
	awstest.StackDriftDetectionInProgress = true
	defer func() { awstest.StackDriftDetectionInProgress = false }()
	awstest.MockCloudFormationForSetup = awstest.BuildMockCloudFormationSvcAll()

	CloudFormationClientFunc = awstest.SetupMockCloudFormation

	resources, err := PollCloudFormationStacks(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Equal(t, *awstest.ExampleDescribeStacks.Stacks[0].StackId, string(resources[0].ID))
	assert.NotEmpty(t, resources)
}
