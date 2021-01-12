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
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestEksClusterList(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvc([]string{"ListClustersPages"})

	out, marker, err := listEKSClusters(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestEksClusterListIterator(t *testing.T) {
	var clusters []*string
	var marker *string

	cont := eksClusterIterator(awstest.ExampleEksListClusters, &clusters, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, clusters, 1)

	for i := 1; i < 50; i++ {
		cont = eksClusterIterator(awstest.ExampleEksListClustersContinue, &clusters, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, clusters, 1+i*2)
	}

	cont = eksClusterIterator(awstest.ExampleEksListClustersContinue, &clusters, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, clusters, 101)
}

func TestEksClusterListError(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvcError([]string{"ListClustersPages"})

	out, marker, err := listEKSClusters(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestEksClusterDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvc([]string{"DescribeCluster"})

	out, err := describeEKSCluster(mockSvc, awstest.ExampleEksClusterName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestEksClusterDescribeDoesNotExist(t *testing.T) {
	mockSvc := &awstest.MockEks{}

	mockSvc.On("DescribeCluster", mock.Anything).
		Return(
			&eks.DescribeClusterOutput{
				Cluster: nil,
			},
			nil,
		)

	out, err := describeEKSCluster(mockSvc, awstest.ExampleEksClusterName)
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestEksClusterDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvcError([]string{"DescribeCluster"})

	out, err := describeEKSCluster(mockSvc, awstest.ExampleEksClusterName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestEksClusterGetProfiles(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvc([]string{"ListFargateProfilesPages", "DescribeFargateProfile"})

	out, err := getEKSFargateProfiles(mockSvc, awstest.ExampleEksClusterNameMulti)
	require.NoError(t, err)
	assert.NotNil(t, out)
	assert.Len(t, out, 2)
}

func TestEksClusterGetProfilesPermissionsError(t *testing.T) {
	mockSvc := &awstest.MockEks{}

	mockSvc.On("ListFargateProfilesPages", mock.Anything).
		Return(
			awserr.New("AccessDeniedException", "status code: 403", errors.New("some error")),
		)

	out, err := getEKSFargateProfiles(mockSvc, awstest.ExampleEksClusterName)
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestEksClusterGetProfilesError(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvcError([]string{"ListFargateProfilesPages", "DescribeFargateProfile"})

	out, err := getEKSFargateProfiles(mockSvc, awstest.ExampleEksClusterName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestEksClusterBuildSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvcAll()

	clusterSnapshot, err := buildEksClusterSnapshot(mockSvc, awstest.ExampleEksClusterName, nil)

	assert.NoError(t, err)
	assert.NotEmpty(t, clusterSnapshot.ARN)
}

func TestEksClusterBuildSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockEksSvcAllError()

	certSnapshot, err := buildEksClusterSnapshot(
		mockSvc,
		awstest.ExampleEksClusterName,
		nil,
	)

	assert.Nil(t, certSnapshot)
	assert.Error(t, err)
}

func TestEksClusterPoller(t *testing.T) {
	awstest.MockEksForSetup = awstest.BuildMockEksSvcAll()

	EksClientFunc = awstest.SetupMockEks

	resources, marker, err := PollEksClusters(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NoError(t, err)
	assert.Equal(t, *awstest.ExampleEksClusterArn, resources[0].ID)
	assert.NotEmpty(t, resources)
	assert.Nil(t, marker)
}

func TestEksClusterPollerError(t *testing.T) {
	resetCache()
	awstest.MockEksForSetup = awstest.BuildMockEksSvcAllError()

	EksClientFunc = awstest.SetupMockEks

	resources, marker, err := PollEksClusters(&awsmodels.ResourcePollerInput{
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
