package api

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
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

func TestCloudSecTemplate(t *testing.T) {
	apiTest := NewAPITest()
	apiTest.Config.Region = endpoints.UsEast1RegionID
	input := &models.GetIntegrationTemplateInput{
		AWSAccountID:       "123456789012",
		IntegrationType:    models.IntegrationTypeAWSScan,
		IntegrationLabel:   "TestLabel-",
		CWEEnabled:         aws.Bool(true),
		RemediationEnabled: aws.Bool(true),
	}

	template, err := ioutil.ReadFile("../../../../deployments/auxiliary/cloudformation/panther-cloudsec-iam.yml")
	require.NoError(t, err)
	apiTest.mockS3.On("GetObject", mock.Anything).Return(&s3.GetObjectOutput{Body: ioutil.NopCloser(bytes.NewReader(template))}, nil)

	result, err := apiTest.GetIntegrationTemplate(input)
	require.NoError(t, err)
	expectedTemplate, err := ioutil.ReadFile("./testdata/panther-cloudsec-iam-updated.yml")
	require.NoError(t, err)
	require.YAMLEq(t, string(expectedTemplate), result.Body)
	require.Equal(t, "panther-cloudsec-setup", result.StackName)
}

func TestLogAnalysisTemplate(t *testing.T) {
	apiTest := NewAPITest()
	input := &models.GetIntegrationTemplateInput{
		AWSAccountID:               "123456789012",
		IntegrationType:            models.IntegrationTypeAWS3,
		IntegrationLabel:           "TestLabel-",
		S3Bucket:                   "test-bucket",
		KmsKey:                     "key-arn",
		ManagedBucketNotifications: true,
	}

	template, err := ioutil.ReadFile("../../../../deployments/auxiliary/cloudformation/panther-log-analysis-iam.yml")
	require.NoError(t, err)
	apiTest.mockS3.On("GetObject", mock.Anything).Return(&s3.GetObjectOutput{Body: ioutil.NopCloser(bytes.NewReader(template))}, nil)

	result, err := apiTest.GetIntegrationTemplate(input)
	require.NoError(t, err)
	expectedTemplate, err := ioutil.ReadFile("./testdata/panther-log-analysis-iam-updated.yml")
	require.NoError(t, err)
	require.YAMLEq(t, string(expectedTemplate), result.Body)
	require.Equal(t, "panther-log-analysis-setup-testlabel-", result.StackName)
}
