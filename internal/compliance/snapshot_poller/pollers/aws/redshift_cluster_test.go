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

func TestRedshiftClusterDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockRedshiftSvc([]string{"DescribeClustersPages"})

	out := describeClusters(mockSvc)
	assert.NotEmpty(t, out)
}

func TestRedshiftClusterDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockRedshiftSvcError([]string{"DescribeClustersPages"})

	out := describeClusters(mockSvc)
	assert.Nil(t, out)
}

func TestRedshiftClusterDescribeLoggingStatus(t *testing.T) {
	mockSvc := awstest.BuildMockRedshiftSvc([]string{"DescribeLoggingStatus"})

	out, err := describeLoggingStatus(mockSvc, awstest.ExampleRDSSnapshotID)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestRedshiftClusterDescribeLoggingStatusError(t *testing.T) {
	mockSvc := awstest.BuildMockRedshiftSvcError([]string{"DescribeLoggingStatus"})

	out, err := describeLoggingStatus(mockSvc, awstest.ExampleRDSSnapshotID)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestRedshiftClusterBuildSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockRedshiftSvcAll()

	clusterSnapshot := buildRedshiftClusterSnapshot(
		mockSvc,
		awstest.ExampleDescribeClustersOutput.Clusters[0],
	)

	assert.NotEmpty(t, clusterSnapshot.LoggingStatus)
	assert.NotEmpty(t, clusterSnapshot.GenericAWSResource)
}

func TestRedshiftCLusterBuildSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockRedshiftSvcAllError()

	clusterSnapshot := buildRedshiftClusterSnapshot(
		mockSvc,
		awstest.ExampleDescribeClustersOutput.Clusters[0],
	)

	assert.NotEmpty(t, clusterSnapshot.GenericAWSResource)
	assert.NotNil(t, clusterSnapshot.VpcId)
	assert.Nil(t, clusterSnapshot.LoggingStatus)
}

func TestRedshiftClusterPoller(t *testing.T) {
	awstest.MockRedshiftForSetup = awstest.BuildMockRedshiftSvcAll()

	RedshiftClientFunc = awstest.SetupMockRedshift

	resources, err := PollRedshiftClusters(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resources)
	cluster := resources[0].Attributes.(*awsmodels.RedshiftCluster)
	assert.Equal(t, aws.String("awsuser"), cluster.MasterUsername)
	assert.Equal(t, aws.String("in-sync"), cluster.ClusterParameterGroups[0].ParameterApplyStatus)
	assert.Equal(t, aws.Int64(5439), cluster.Endpoint.Port)
	assert.Equal(t, aws.String("LEADER"), cluster.ClusterNodes[0].NodeRole)
	assert.False(t, *cluster.EnhancedVpcRouting)
}

func TestRedshiftClusterPollerError(t *testing.T) {
	awstest.MockRedshiftForSetup = awstest.BuildMockRedshiftSvcAllError()

	RedshiftClientFunc = awstest.SetupMockRedshift

	resources, err := PollRDSInstances(&awsmodels.ResourcePollerInput{
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
