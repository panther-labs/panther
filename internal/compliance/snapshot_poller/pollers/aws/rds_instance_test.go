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
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestRDSInstanceDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvc([]string{"DescribeDBInstancesPages"})

	out, marker, err := describeDBInstances(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestRdsInstanceListIterator(t *testing.T) {
	var instances []*rds.DBInstance
	var marker *string

	cont := rdsInstanceIterator(awstest.ExampleDescribeDBInstancesOutput, &instances, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, instances, 1)

	for i := 1; i < 10; i++ {
		cont = rdsInstanceIterator(awstest.ExampleDescribeDBInstancesOutputContinue, &instances, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, instances, 1+i*2)
	}

	cont = rdsInstanceIterator(awstest.ExampleDescribeDBInstancesOutputContinue, &instances, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, instances, 21)
}

func TestRDSInstanceDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvcError([]string{"DescribeDBInstancesPages"})

	out, marker, err := describeDBInstances(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestRDSInstanceDescribeSnapshots(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvc([]string{"DescribeDBSnapshotsPages"})

	out, err := describeDBSnapshots(mockSvc, awstest.ExampleRDSInstanceName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestRDSInstanceDescribeSnapshotsError(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvcError([]string{"DescribeDBSnapshotsPages"})

	out, err := describeDBSnapshots(mockSvc, awstest.ExampleRDSInstanceName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestRDSInstanceListTagsForResource(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvc([]string{"ListTagsForResource"})

	out, err := listTagsForResourceRds(mockSvc, awstest.ExampleRDSInstanceName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestRDSInstanceListTagsForResourceError(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvcError([]string{"ListTagsForResource"})

	out, err := listTagsForResourceRds(mockSvc, awstest.ExampleRDSInstanceName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestRDSInstanceDescribeSnapshotAttributes(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvc([]string{"DescribeDBSnapshotAttributes"})

	out, err := describeDBSnapshotAttributes(mockSvc, awstest.ExampleRDSSnapshotID)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestRDSInstanceDescribeSnapshotAttributesError(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvcError([]string{"DescribeDBSnapshotAttributes"})

	out, err := describeDBSnapshotAttributes(mockSvc, awstest.ExampleRDSSnapshotID)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestRDSInstanceBuildSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvcAll()

	instanceSnapshot, err := buildRDSInstanceSnapshot(
		mockSvc,
		awstest.ExampleDescribeDBInstancesOutput.DBInstances[0],
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, instanceSnapshot.ARN)
	assert.NotEmpty(t, instanceSnapshot.SnapshotAttributes)
}

func TestRDSInstanceBuildSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockRdsSvcAllError()

	instance, err := buildRDSInstanceSnapshot(
		mockSvc,
		awstest.ExampleDescribeDBInstancesOutput.DBInstances[0],
	)

	assert.Error(t, err)
	assert.Nil(t, instance)
}

func TestRDSInstancePoller(t *testing.T) {
	awstest.MockRdsForSetup = awstest.BuildMockRdsSvcAll()

	RDSClientFunc = awstest.SetupMockRds

	resources, marker, err := PollRDSInstances(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NotEmpty(t, resources)
	instance := resources[0].Attributes.(*awsmodels.RDSInstance)
	assert.Equal(t, aws.String("superuser"), instance.MasterUsername)
	assert.Equal(t,
		aws.String("restore"),
		instance.SnapshotAttributes[0].DBSnapshotAttributes[0].AttributeName,
	)
	assert.Equal(t, aws.Int64(3306), instance.Endpoint.Port)
	assert.NotEmpty(t, instance.DBSubnetGroup.Subnets)
	assert.Equal(t, aws.String("in-sync"), instance.OptionGroupMemberships[0].Status)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestRDSInstancePollerError(t *testing.T) {
	resetCache()
	awstest.MockRdsForSetup = awstest.BuildMockRdsSvcAllError()

	RDSClientFunc = awstest.SetupMockRds

	resources, marker, err := PollRDSInstances(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Empty(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}
