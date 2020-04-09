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

func TestDynamoDBList(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvc([]string{"ListTablesPages"})

	out, err := listTables(mockSvc)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestDynamoDBListError(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvcError([]string{"ListTablesPages"})

	out, err := listTables(mockSvc)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestDynamoDBDescribeTable(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvc([]string{"DescribeTable"})

	out := describeTable(mockSvc, awstest.ExampleTableName)
	assert.NotEmpty(t, out)
	assert.Equal(t, "example-table", *out.TableName)
}

func TestDynamoDBDescribeTableError(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvcError([]string{"DescribeTable"})

	out := describeTable(mockSvc, awstest.ExampleTableName)
	assert.Nil(t, out)
}

func TestDynamoDBListTagsOfResource(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvc([]string{"ListTagsOfResource"})

	out, err := listTagsOfResource(mockSvc, awstest.ExampleTableName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestDynamoDBListTagsOfResourceError(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvcError([]string{"ListTagsOfResource"})

	out, err := listTagsOfResource(mockSvc, awstest.ExampleTableName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestDynamoDBDescribeTimeToLive(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvc([]string{"DescribeTimeToLive"})

	out, err := describeTimeToLive(mockSvc, awstest.ExampleTableName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestDynamoDBDescribeTimeToLiveError(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvcError([]string{"DescribeTimeToLive"})

	out, err := describeTimeToLive(mockSvc, awstest.ExampleTableName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestBuildDynamoDBSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvcAll()
	mockApplicationAutoScalerSvc := awstest.BuildMockApplicationAutoScalingSvcAll()

	tableSnapshot := buildDynamoDBTableSnapshot(
		mockSvc,
		mockApplicationAutoScalerSvc,
		awstest.ExampleTableName,
	)

	assert.NotNil(t, tableSnapshot.ARN)
	assert.NotEmpty(t, tableSnapshot.GlobalSecondaryIndexes)
}

func TestBuildDynamoDBSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockDynamoDBSvcAllError()
	mockApplicationAutoScalerSvc := awstest.BuildMockApplicationAutoScalingSvcAllError()

	tableSnapshot := buildDynamoDBTableSnapshot(
		mockSvc,
		mockApplicationAutoScalerSvc,
		awstest.ExampleTableName,
	)

	var expected *awsmodels.DynamoDBTable
	assert.Equal(t, expected, tableSnapshot)
}

func TestDynamoDBPoller(t *testing.T) {
	awstest.MockDynamoDBForSetup = awstest.BuildMockDynamoDBSvcAll()
	awstest.MockApplicationAutoScalingForSetup = awstest.BuildMockApplicationAutoScalingSvcAll()

	DynamoDBClientFunc = awstest.SetupMockDynamoDB
	ApplicationAutoScalingClientFunc = awstest.SetupMockApplicationAutoScaling

	resources, err := PollDynamoDBTables(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resources)
	table := resources[0].Attributes.(*awsmodels.DynamoDBTable)
	// Test a string, nested struct/string, and Int64 in Details
	assert.Equal(t, aws.String("example-table"), table.Name)
	assert.Equal(t, aws.String("primary_key"), table.KeySchema[0].AttributeName)
	assert.Equal(t, aws.Int64(1000), table.TableSizeBytes)
	// Test a String and Int64 in AutoScalingDescriptions
	assert.Equal(t, aws.String("table/example-table"), table.AutoScalingDescriptions[0].ResourceId)
	assert.Equal(t, aws.Int64(4000), table.AutoScalingDescriptions[0].MaxCapacity)
}

func TestDynamoDBPollerError(t *testing.T) {
	awstest.MockDynamoDBForSetup = awstest.BuildMockDynamoDBSvcAllError()
	awstest.MockApplicationAutoScalingForSetup = awstest.BuildMockApplicationAutoScalingSvcAllError()

	DynamoDBClientFunc = awstest.SetupMockDynamoDB

	resources, err := PollDynamoDBTables(&awsmodels.ResourcePollerInput{
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
