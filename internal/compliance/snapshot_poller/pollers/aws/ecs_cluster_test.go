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

	out, marker, err := listClusters(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestEcsClusterListIterator(t *testing.T) {
	var clusters []*string
	var marker *string

	cont := ecsClusterIterator(awstest.ExampleListClusters, &clusters, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, clusters, 1)

	for i := 1; i < 50; i++ {
		cont = ecsClusterIterator(awstest.ExampleListClustersContinue, &clusters, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, clusters, 1+i*2)
	}

	cont = ecsClusterIterator(awstest.ExampleListClustersContinue, &clusters, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, clusters, 101)
}

func TestEcsClusterListError(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvcError([]string{"ListClustersPages"})

	out, marker, err := listClusters(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
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

	clusterSnapshot, err := buildEcsClusterSnapshot(
		mockSvc,
		awstest.ExampleListClusters.ClusterArns[0],
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, clusterSnapshot.ARN)
	assert.Equal(t, "Value1", *clusterSnapshot.Tags["Key1"])
}

func TestEcsClusterBuildSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockEcsSvcAllError()

	certSnapshot, err := buildEcsClusterSnapshot(
		mockSvc,
		awstest.ExampleListClusters.ClusterArns[0],
	)

	assert.Nil(t, certSnapshot)
	assert.Error(t, err)
}

func TestEcsClusterPoller(t *testing.T) {
	awstest.MockEcsForSetup = awstest.BuildMockEcsSvcAll()

	EcsClientFunc = awstest.SetupMockEcs

	resources, marker, err := PollEcsClusters(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NoError(t, err)
	assert.Equal(t, *awstest.ExampleClusterArn, string(resources[0].ID))
	assert.NotEmpty(t, resources)
	assert.Nil(t, marker)
}

func TestEcsClusterPollerError(t *testing.T) {
	awstest.MockEcsForSetup = awstest.BuildMockEcsSvcAllError()

	EcsClientFunc = awstest.SetupMockEcs

	resources, marker, err := PollEcsClusters(&awsmodels.ResourcePollerInput{
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
