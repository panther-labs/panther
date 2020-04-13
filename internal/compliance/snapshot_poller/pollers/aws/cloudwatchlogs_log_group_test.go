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

func TestCloudWatchLogsLogGroupsDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvc([]string{"DescribeLogGroupsPages"})

	out, err := describeLogGroups(mockSvc)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudWatchLogsLogGroupsDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvcError([]string{"DescribeLogGroupsPages"})

	out, err := describeLogGroups(mockSvc)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestCloudWatchLogsLogGroupsListTags(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvc([]string{"ListTagsLogGroup"})

	out := listTagsLogGroup(mockSvc, awstest.ExampleDescribeLogGroups.LogGroups[0].LogGroupName)
	assert.NotEmpty(t, out)
}

func TestCloudWatchLogsLogGroupsListTagsError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvcError([]string{"ListTagsLogGroup"})

	out := listTagsLogGroup(mockSvc, awstest.ExampleDescribeLogGroups.LogGroups[0].LogGroupName)
	assert.Nil(t, out)
}

func TestBuildCloudWatchLogsLogGroupSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvcAll()

	certSnapshot := buildCloudWatchLogsLogGroupSnapshot(
		mockSvc,
		awstest.ExampleDescribeLogGroups.LogGroups[0],
	)

	assert.NotNil(t, certSnapshot.ARN)
	assert.NotNil(t, certSnapshot.StoredBytes)
	assert.Equal(t, "LogGroup-1", *certSnapshot.Name)
}

func TestCloudWatchLogsLogGroupPoller(t *testing.T) {
	awstest.MockCloudWatchLogsForSetup = awstest.BuildMockCloudWatchLogsSvcAll()

	CloudWatchLogsClientFunc = awstest.SetupMockCloudWatchLogs

	resources, err := PollCloudWatchLogsLogGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resources)
}

func TestCloudWatchLogsLogGroupPollerError(t *testing.T) {
	awstest.MockCloudWatchLogsForSetup = awstest.BuildMockCloudWatchLogsSvcAllError()

	AcmClientFunc = awstest.SetupMockAcm

	resources, err := PollCloudWatchLogsLogGroups(&awsmodels.ResourcePollerInput{
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
