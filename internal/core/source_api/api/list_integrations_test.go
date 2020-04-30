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
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/internal/core/source_api/ddb/modelstest"
)

func TestListIntegrations(t *testing.T) {
	lastScanEndTime, err := time.Parse(time.RFC3339, "2019-04-10T23:00:00Z")
	require.NoError(t, err)

	lastScanStartTime, err := time.Parse(time.RFC3339, "2019-04-10T22:59:00Z")
	require.NoError(t, err)

	dynamoClient = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			MockScanAttributes: []map[string]*dynamodb.AttributeValue{
				{
					"awsAccountId":         {S: aws.String("123456789012")},
					"eventStatus":          {S: aws.String(models.StatusOK)},
					"integrationId":        {S: aws.String(testIntegrationID)},
					"integrationLabel":     {S: aws.String(testIntegrationLabel)},
					"integrationType":      {S: aws.String(models.IntegrationTypeAWSScan)},
					"lastScanEndTime":      {S: aws.String(lastScanEndTime.Format(time.RFC3339))},
					"lastScanErrorMessage": {S: aws.String("")},
					"lastScanStartTime":    {S: aws.String(lastScanStartTime.Format(time.RFC3339))},
					"scanIntervalMins":     {N: aws.String(strconv.Itoa(1440))},
					"scanStatus":           {S: aws.String(models.StatusOK)},
				},
			},
			TestErr: false,
		},
		TableName: "test",
	}

	expected := &models.SourceIntegration{
		SourceIntegrationMetadata: &models.SourceIntegrationMetadata{
			AWSAccountID:     aws.String("123456789012"),
			IntegrationID:    aws.String(testIntegrationID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
			ScanIntervalMins: aws.Int(1440),
		},
		SourceIntegrationStatus: &models.SourceIntegrationStatus{
			ScanStatus:  aws.String(models.StatusOK),
			EventStatus: aws.String(models.StatusOK),
		},
		SourceIntegrationScanInformation: &models.SourceIntegrationScanInformation{
			LastScanEndTime:      &lastScanEndTime,
			LastScanErrorMessage: aws.String(""),
			LastScanStartTime:    &lastScanStartTime,
		},
	}
	out, err := apiTest.ListIntegrations(&models.ListIntegrationsInput{})

	require.NoError(t, err)
	require.NotEmpty(t, out)
	assert.Len(t, out, 1)
	assert.Equal(t, expected, out[0])
}

// An empty list of integrations is returned instead of null
func TestListIntegrationsEmpty(t *testing.T) {
	dynamoClient = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			MockScanAttributes: []map[string]*dynamodb.AttributeValue{},
			TestErr:            false,
		},
		TableName: "test",
	}

	out, err := apiTest.ListIntegrations(&models.ListIntegrationsInput{})

	require.NoError(t, err)
	assert.Equal(t, []*models.SourceIntegration{}, out)
}

func TestHandleListIntegrationsScanError(t *testing.T) {
	dynamoClient = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			MockScanAttributes: []map[string]*dynamodb.AttributeValue{},
			TestErr:            true,
		},
		TableName: "test",
	}

	out, err := apiTest.ListIntegrations(&models.ListIntegrationsInput{})

	require.NotNil(t, err)
	assert.Nil(t, out)
}
