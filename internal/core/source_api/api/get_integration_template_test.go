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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestCloudSecTemplate(t *testing.T) {
	s3Mock := &testutils.S3Mock{}
	templateS3Client = s3Mock
	awsSession = &session.Session{
		Config: &aws.Config{
			Region: aws.String(endpoints.UsEast1RegionID),
		},
	}
	input := &models.GetIntegrationTemplateInput{
		AWSAccountID:       aws.String("123456789012"),
		IntegrationType:    aws.String(models.IntegrationTypeAWSScan),
		IntegrationLabel:   aws.String("TestLabel-"),
		CWEEnabled:         aws.Bool(true),
		RemediationEnabled: aws.Bool(true),
	}

	template, err := ioutil.ReadFile("../../../../deployments/auxiliary/cloudformation/panther-cloudsec-iam.yml")
	require.NoError(t, err)
	s3Mock.On("GetObject", mock.Anything).Return(&s3.GetObjectOutput{Body: ioutil.NopCloser(bytes.NewReader(template))}, nil)

	result, err := API{}.GetIntegrationTemplate(input)
	require.NoError(t, err)
	expectedTemplate, err := ioutil.ReadFile("./testdata/panther-cloudsec-iam-updated.yml")
	require.NoError(t, err)
	require.YAMLEq(t, string(expectedTemplate), *result.Body)
	require.Equal(t, "panther-cloudsec-setup", *result.StackName)
}

func TestLogAnalysisTemplate(t *testing.T) {
	s3Mock := &testutils.S3Mock{}
	templateS3Client = s3Mock
	input := &models.GetIntegrationTemplateInput{
		AWSAccountID:     aws.String("123456789012"),
		IntegrationType:  aws.String(models.IntegrationTypeAWS3),
		IntegrationLabel: aws.String("TestLabel-"),
		S3Bucket:         aws.String("test-bucket"),
		S3Prefix:         aws.String("prefix"),
		KmsKey:           aws.String("key-arn"),
	}

	template, err := ioutil.ReadFile("../../../../deployments/auxiliary/cloudformation/panther-log-analysis-iam.yml")
	require.NoError(t, err)
	s3Mock.On("GetObject", mock.Anything).Return(&s3.GetObjectOutput{Body: ioutil.NopCloser(bytes.NewReader(template))}, nil)

	result, err := API{}.GetIntegrationTemplate(input)
	require.NoError(t, err)
	expectedTemplate, err := ioutil.ReadFile("./testdata/panther-log-analysis-iam-updated.yml")
	require.NoError(t, err)
	require.YAMLEq(t, string(expectedTemplate), *result.Body)
	require.Equal(t, "panther-log-analysis-setup-testlabel-", *result.StackName)
}
