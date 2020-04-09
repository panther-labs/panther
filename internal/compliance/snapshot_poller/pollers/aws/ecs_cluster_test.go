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

	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestEcsClusterList(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvc([]string{"ListClustersPages"})

	out := listClusters(mockSvc)
	assert.NotEmpty(t, out)
}

func TestEcsClusterListError(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvcError([]string{"ListClustersPages"})

	out := listClusters(mockSvc)
	assert.Nil(t, out)
}

func TestEcsClusterDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvc([]string{"DescribeClusters"})

	out, err := describeCluster(mockSvc, awstest.ExampleClusterArn)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestEcsClusterDescribeDoesNotExist(t *testing.T) {
	mockSvc := &awstest.MockEcs{}
	mockSvc.On("DescribeClusters", mock.Anything).
		Return(
			&ecs.DescribeClustersOutput{
				Clusters: nil,
			},
			nil,
		)

	out, err := describeCluster(mockSvc, awstest.ExampleClusterArn)
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestEcsClusterDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvcError([]string{"DescribeClusters"})

	out, err := describeCluster(mockSvc, awstest.ExampleClusterArn)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestEcsClusterBuildSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvcAll()

	clusterSnapshot := buildEcsClusterSnapshot(
		mockSvc,
		awstest.ExampleListClusters.ClusterArns[0],
	)

	assert.NotEmpty(t, clusterSnapshot.ARN)
	assert.Equal(t, "Value1", *clusterSnapshot.Tags["Key1"])
}

func TestEcsClusterBuildSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvcAllError()

	certSnapshot := buildEcsClusterSnapshot(
		mockSvc,
		awstest.ExampleListClusters.ClusterArns[0],
	)

	assert.Nil(t, certSnapshot)
}

func TestEcsClusterPoller(t *testing.T) {
	awstest.MockEcsForSetup = awstest.BuildMockEcsSvcAll()

	EcsClientFunc = awstest.SetupMockEcs

	resources, err := PollEcsClusters(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Equal(t, *awstest.ExampleClusterArn, string(resources[0].ID))
	assert.NotEmpty(t, resources)
}

func TestEcsClusterPollerError(t *testing.T) {
	awstest.MockEcsForSetup = awstest.BuildMockEcsSvcAllError()

	EcsClientFunc = awstest.SetupMockEcs

	resources, err := PollEcsClusters(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
}
