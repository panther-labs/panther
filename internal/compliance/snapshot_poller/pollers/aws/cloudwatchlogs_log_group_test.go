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

	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestCloudWatchLogsLogGroupsDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvc([]string{"DescribeLogGroupsPages"})

	out, marker, err := describeLogGroups(mockSvc, nil)
	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.NotEmpty(t, out)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestCloudWatchLogsLogGroupListIterator(t *testing.T) {
	var logGroups []*cloudwatchlogs.LogGroup
	var marker *string

	cont := loggroupIterator(awstest.ExampleDescribeLogGroups, &logGroups, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, logGroups, 2)

	for i := 2; i < 5; i++ {
		cont = loggroupIterator(awstest.ExampleDescribeLogGroupsContinue, &logGroups, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, logGroups, i*2)
	}

	cont = loggroupIterator(awstest.ExampleDescribeLogGroupsContinue, &logGroups, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, logGroups, 10)
}

func TestCloudWatchLogsLogGroupsDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvcError([]string{"DescribeLogGroupsPages"})

	out, marker, err := describeLogGroups(mockSvc, nil)
	require.Error(t, err)
	assert.Nil(t, marker)
	assert.Nil(t, out)
}

func TestCloudWatchLogsLogGroupsListTags(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvc([]string{"ListTagsLogGroup"})

	out, err := listTagsLogGroup(mockSvc, awstest.ExampleDescribeLogGroups.LogGroups[0].LogGroupName)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestCloudWatchLogsLogGroupsListTagsError(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvcError([]string{"ListTagsLogGroup"})

	out, err := listTagsLogGroup(mockSvc, awstest.ExampleDescribeLogGroups.LogGroups[0].LogGroupName)
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestBuildCloudWatchLogsLogGroupSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockCloudWatchLogsSvcAll()

	certSnapshot, err := buildCloudWatchLogsLogGroupSnapshot(
		mockSvc,
		awstest.ExampleDescribeLogGroups.LogGroups[0],
	)

	assert.NoError(t, err)
	assert.NotNil(t, certSnapshot.ARN)
	assert.NotNil(t, certSnapshot.StoredBytes)
	assert.Equal(t, "LogGroup-1", *certSnapshot.Name)
}

func TestCloudWatchLogsLogGroupPoller(t *testing.T) {
	awstest.MockCloudWatchLogsForSetup = awstest.BuildMockCloudWatchLogsSvcAll()

	CloudWatchLogsClientFunc = awstest.SetupMockCloudWatchLogs

	resources, marker, err := PollCloudWatchLogsLogGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.NotEmpty(t, resources)
}

func TestCloudWatchLogsLogGroupPollerError(t *testing.T) {
	resetCache()
	awstest.MockCloudWatchLogsForSetup = awstest.BuildMockCloudWatchLogsSvcAllError()

	AcmClientFunc = awstest.SetupMockAcm

	resources, marker, err := PollCloudWatchLogsLogGroups(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.Error(t, err)
	assert.Nil(t, marker)
	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
}
