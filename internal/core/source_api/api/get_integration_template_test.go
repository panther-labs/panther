package api

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"io/ioutil"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

func TestCloudSecTemplate(t *testing.T) {
	input := &models.GetIntegrationTemplateInput{
		AWSAccountID:       aws.String("123456789012"),
		IntegrationType:    aws.String(models.IntegrationTypeAWSScan),
		IntegrationLabel:   aws.String("TestLabel-"),
		CWEEnabled:         aws.Bool(true),
		RemediationEnabled: aws.Bool(true),
	}

	result, err := API{}.GetIntegrationTemplate(input)
	require.NoError(t, err)
	expectedTemplate, err := ioutil.ReadFile("./testdata/panther-cloudsec-iam-updated.yml")
	require.NoError(t, err)
	require.YAMLEq(t, string(expectedTemplate), *result.Body)
}

func TestLogAnalysisTemplate(t *testing.T) {
	input := &models.GetIntegrationTemplateInput{
		AWSAccountID:     aws.String("123456789012"),
		IntegrationType:  aws.String(models.IntegrationTypeAWS3),
		IntegrationLabel: aws.String("TestLabel-"),
		S3Bucket:         aws.String("test-bucket"),
		S3Prefix:         aws.String("prefix"),
		KmsKey:           aws.String("key-arn"),
	}

	result, err := API{}.GetIntegrationTemplate(input)
	require.NoError(t, err)
	expectedTemplate, err := ioutil.ReadFile("./testdata/panther-log-analysis-iam-updated.yml")
	require.NoError(t, err)
	require.YAMLEq(t, string(expectedTemplate), *result.Body)
}
