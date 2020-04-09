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

func TestGuardDutyListDetectors(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvc([]string{"ListDetectorsPages"})

	out := listDetectors(mockSvc)
	assert.NotEmpty(t, out)
}

func TestGuardDutyListDetectorsError(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvcError([]string{"ListDetectorsPages"})

	out := listDetectors(mockSvc)
	assert.Nil(t, out)
}

func TestGuardDutyGetMasterAccount(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvc([]string{"GetMasterAccount"})

	out, err := getMasterAccount(mockSvc, awstest.ExampleDetectorID)

	assert.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestGuardDutyGetMasterAccountError(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvcError([]string{"GetMasterAccount"})

	out, err := getMasterAccount(mockSvc, awstest.ExampleDetectorID)

	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestGuardDutyGetDetector(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvc([]string{"GetDetector"})

	out, err := getDetector(mockSvc, awstest.ExampleDetectorID)

	assert.NoError(t, err)
	assert.NotEmpty(t, out)
	assert.NotNil(t, out.Tags)
	assert.NotNil(t, out.UpdatedAt)
	assert.NotNil(t, out.ServiceRole)
}

func TestGuardDutyGetDetectorError(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvcError([]string{"GetDetector"})

	out, err := getDetector(mockSvc, awstest.ExampleDetectorID)

	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestBuildGuardDutyDetectorSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvcAll()

	detectorSnapshot := buildGuardDutyDetectorSnapshot(
		mockSvc,
		awstest.ExampleDetectorID,
	)

	assert.NotEmpty(t, detectorSnapshot.Master)
	assert.Equal(t, awstest.ExampleDetectorID, detectorSnapshot.ID)
}

func TestBuildGuardDutyDetectorSnapshotError(t *testing.T) {
	mockSvc := awstest.BuildMockGuardDutySvcAllError()

	detectorSnapshot := buildGuardDutyDetectorSnapshot(
		mockSvc,
		awstest.ExampleDetectorID,
	)

	assert.Nil(t, detectorSnapshot)
}

func TestGuardDutyDetectorsPoller(t *testing.T) {
	awstest.MockGuardDutyForSetup = awstest.BuildMockGuardDutySvcAll()

	GuardDutyClientFunc = awstest.SetupMockGuardDuty

	resources, err := PollGuardDutyDetectors(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Regexp(
		t,
		regexp.MustCompile(`123456789012:[^:]*:AWS\.GuardDuty\.Detector`),
		resources[0].ID,
	)
	assert.Regexp(
		t,
		regexp.MustCompile(`123456789012::AWS\.GuardDuty\.Detector\.Meta`),
		resources[3].ID,
	)
	assert.NotEmpty(t, resources)
	// Three regions + meta resource
	assert.Len(t, resources, 4)
	assert.IsType(t, &awsmodels.GuardDutyMeta{}, resources[3].Attributes)
	assert.Len(t, resources[3].Attributes.(*awsmodels.GuardDutyMeta).Detectors, 3)
}

func TestGuardDutyDetectorsPollerError(t *testing.T) {
	awstest.MockGuardDutyForSetup = awstest.BuildMockGuardDutySvcAllError()

	GuardDutyClientFunc = awstest.SetupMockGuardDuty

	resources, err := PollGuardDutyDetectors(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	// Should only contain meta resource
	require.Len(t, resources, 1)
}
