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
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestDescribeConfigurationRecorders(t *testing.T) {
	mockSvc := awstest.BuildMockConfigServiceSvc([]string{"DescribeConfigurationRecorders"})

	out, err := describeConfigurationRecorders(mockSvc)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestDescribeConfigurationRecordersError(t *testing.T) {
	mockSvc := awstest.BuildMockConfigServiceSvcError([]string{"DescribeConfigurationRecorders"})

	out, err := describeConfigurationRecorders(mockSvc)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestDescribeConfigurationRecorderStatus(t *testing.T) {
	mockSvc := awstest.BuildMockConfigServiceSvc([]string{"DescribeConfigurationRecorderStatus"})

	out, err := describeConfigurationRecorderStatus(mockSvc, awstest.ExampleConfigName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestDescribeConfigurationRecorderStatusError(t *testing.T) {
	mockSvc := awstest.BuildMockConfigServiceSvcError([]string{"DescribeConfigurationRecorderStatus"})

	out, err := describeConfigurationRecorderStatus(mockSvc, awstest.ExampleConfigName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestBuildConfigServiceSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockConfigServiceSvcAll()

	out := buildConfigServiceSnapshot(
		mockSvc,
		awstest.ExampleDescribeConfigurationRecorders.ConfigurationRecorders[0],
		"us-west-2",
	)
	assert.NotEmpty(t, out)
}

func TestBuildConfigServiceSnapshotError(t *testing.T) {
	mockSvc := awstest.BuildMockConfigServiceSvcAllError()

	out := buildConfigServiceSnapshot(
		mockSvc,
		awstest.ExampleDescribeConfigurationRecorders.ConfigurationRecorders[0],
		"us-west-2",
	)
	assert.NotEmpty(t, out)
}

func TestPollConfigServices(t *testing.T) {
	awstest.MockConfigServiceForSetup = awstest.BuildMockConfigServiceSvcAll()

	ConfigServiceClientFunc = awstest.SetupMockConfigService

	resources, err := PollConfigServices(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resources)

	assert.IsType(t, &awsmodels.ConfigService{}, resources[0].Attributes)
	assert.Regexp(
		t, regexp.MustCompile(`123456789012\:.*\:AWS.Config.Recorder`), string(resources[0].ID),
	)

	assert.IsType(t, &awsmodels.ConfigServiceMeta{}, resources[len(resources)-1].Attributes)
	assert.Equal(t, "123456789012::AWS.Config.Recorder.Meta", string(resources[len(resources)-1].ID))
}

func TestPollConfigServicesError(t *testing.T) {
	awstest.MockConfigServiceForSetup = awstest.BuildMockConfigServiceSvcAllError()

	ConfigServiceClientFunc = awstest.SetupMockConfigService

	resources, err := PollConfigServices(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	// The meta resource should still send.
	assert.Len(t, resources, 1)
}
