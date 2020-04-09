package aws

/**
 * A Cloud-Native SIEM for the Modern Security Team
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

func TestAcmCertificateList(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvc([]string{"ListCertificatesPages"})

	out := listCertificates(mockSvc)
	assert.NotEmpty(t, out)
}

func TestAcmCertificateListError(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvcError([]string{"ListCertificatesPages"})

	out := listCertificates(mockSvc)
	assert.Nil(t, out)
}

func TestAcmCertificateDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvc([]string{"DescribeCertificate"})

	out, err := describeCertificate(mockSvc, awstest.ExampleCertificateArn)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestAcmCertificateDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvcError([]string{"DescribeCertificate"})

	out, err := describeCertificate(mockSvc, awstest.ExampleCertificateArn)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestAcmCertificateListTags(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvc([]string{"ListTagsForCertificate"})

	out, err := listTagsForCertificate(mockSvc, awstest.ExampleCertificateArn)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestAcmCertificateListTagsError(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvcError([]string{"ListTagsForCertificate"})

	out, err := listTagsForCertificate(mockSvc, awstest.ExampleCertificateArn)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestAcmCertificateBuildSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvcAll()

	certSnapshot := buildAcmCertificateSnapshot(
		mockSvc,
		awstest.ExampleListCertificatesOutput.CertificateSummaryList[0].CertificateArn,
	)

	assert.NotEmpty(t, certSnapshot.ARN)
	assert.Equal(t, "Value1", *certSnapshot.Tags["Key1"])
}

func TestAcmCertificateBuildSnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockAcmSvcAllError()

	certSnapshot := buildAcmCertificateSnapshot(
		mockSvc,
		awstest.ExampleListCertificatesOutput.CertificateSummaryList[0].CertificateArn,
	)

	assert.Nil(t, certSnapshot)
}

func TestAcmCertificatePoller(t *testing.T) {
	awstest.MockAcmForSetup = awstest.BuildMockAcmSvcAll()

	AcmClientFunc = awstest.SetupMockAcm

	resources, err := PollAcmCertificates(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Regions:             awstest.ExampleRegions,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NoError(t, err)
	assert.Equal(t, *awstest.ExampleCertificateArn, string(resources[0].ID))
	assert.NotEmpty(t, resources)
}

func TestAcmCertificatePollerError(t *testing.T) {
	awstest.MockAcmForSetup = awstest.BuildMockAcmSvcAllError()

	AcmClientFunc = awstest.SetupMockAcm

	resources, err := PollAcmCertificates(&awsmodels.ResourcePollerInput{
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
