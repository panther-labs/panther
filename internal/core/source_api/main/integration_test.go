package main

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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	functionName = "panther-source-api"
	tableName    = "panther-source-integrations"
	testUserID   = "97c4db4e-61d5-40a7-82de-6dd63b199bd2"
	testUserID2  = "1ffa65fe-54fc-49ff-aafc-3f8bd386079e"
)

type generatedIDs struct {
	integrationID *string
}

var (
	integrationTest bool
	sess            *session.Session
	lambdaClient    *lambda.Lambda

	generatedIntegrationIDs []*generatedIDs
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	os.Exit(m.Run())
}

func TestIntegration(t *testing.T) {
	//if !integrationTest {
	//	t.Skip()
	//}
	// TODO This integration test currently fails since it tries to do healthcheck when adding integration.
	// This causes all subsequent tests to fail
	// See https://github.com/panther-labs/panther/issues/394
	t.Skip()

	sess = session.Must(session.NewSession())
	lambdaClient = lambda.New(sess)

	// Reset backend state - erase dynamo table
	require.NoError(t, testutils.ClearDynamoTable(sess, tableName))

	t.Run("API", func(t *testing.T) {
		t.Run("PutIntegrations", putIntegrations)
		t.Run("GetEnabledIntegrations", getEnabledIntegrations)
		t.Run("DeleteIntegrations", deleteSingleIntegration)
		t.Run("DeleteSingleIntegrationThatDoesNotExist", deleteSingleIntegrationThatDoesNotExist)
		t.Run("UpdateIntegrationSettings", updateIntegrationSettings)
		t.Run("UpdateIntegrationLastScanStart", updateIntegrationLastScanStart)
		t.Run("UpdateIntegrationLastScanEnd", updateIntegrationLastScanEnd)
		t.Run("UpdateIntegrationLastScanEndWithError", updateIntegrationLastScanEndWithError)
	})
}

func putIntegrations(t *testing.T) {
	input := &models.LambdaInput{
		PutIntegration: &models.PutIntegrationInput{
			SkipScanQueue: aws.Bool(true),
			Integrations: []*models.PutIntegrationSettings{
				{
					AWSAccountID:     aws.String("888888888888"),
					ScanEnabled:      aws.Bool(true),
					IntegrationLabel: aws.String("ThisAccount"),
					IntegrationType:  aws.String("aws-scan"),
					ScanIntervalMins: aws.Int(60),
					UserID:           aws.String(testUserID),
				},
				{
					AWSAccountID:     aws.String("111111111111"),
					ScanEnabled:      aws.Bool(false),
					IntegrationLabel: aws.String("TestAWS"),
					IntegrationType:  aws.String("aws-scan"),
					ScanIntervalMins: aws.Int(60),
					UserID:           aws.String(testUserID),
				},
				{
					AWSAccountID:     aws.String("555555555555"),
					ScanEnabled:      aws.Bool(true),
					IntegrationLabel: aws.String("StageAWS"),
					IntegrationType:  aws.String("aws-scan"),
					ScanIntervalMins: aws.Int(1440),
					UserID:           aws.String(testUserID2),
				},
			},
		},
	}
	var output []*models.SourceIntegrationMetadata
	err := genericapi.Invoke(lambdaClient, functionName, &input, &output)
	require.NoError(t, err)
}

func getEnabledIntegrations(t *testing.T) {
	input := &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{
			IntegrationType: aws.String("aws-scan"),
		},
	}
	var output []*models.SourceIntegration

	err := genericapi.Invoke(lambdaClient, functionName, &input, &output)
	require.NoError(t, err)
	require.Len(t, output, 2)

	for _, integration := range output {
		require.NotEmpty(t, integration.IntegrationID)
		generatedIntegrationIDs = append(generatedIntegrationIDs, &generatedIDs{
			integrationID: integration.IntegrationID,
		})
	}

	// Check for integrations that do not exist

	input = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{
			IntegrationType: aws.String("aws-s3"),
		},
	}

	err = genericapi.Invoke(lambdaClient, functionName, &input, &output)
	require.NoError(t, err)
	require.Len(t, output, 0)
}

func deleteSingleIntegration(t *testing.T) {
	input := &models.LambdaInput{
		DeleteIntegration: &models.DeleteIntegrationInput{
			IntegrationID: generatedIntegrationIDs[0].integrationID,
		},
	}
	require.NoError(t, genericapi.Invoke(lambdaClient, functionName, input, nil))
}

func deleteSingleIntegrationThatDoesNotExist(t *testing.T) {
	input := &models.LambdaInput{
		DeleteIntegration: &models.DeleteIntegrationInput{
			// Random UUID that shouldn't exist in the table should not throw an error
			IntegrationID: aws.String("e87f7365-c927-441a-bd38-99de521a4fd6"),
		},
	}
	assert.Error(t, genericapi.Invoke(lambdaClient, functionName, input, nil))
}

func updateIntegrationSettings(t *testing.T) {
	integrationToUpdate := generatedIntegrationIDs[1]
	newLabel := "StageEnvAWS"
	newScanInterval := 180

	input := &models.LambdaInput{
		UpdateIntegrationSettings: &models.UpdateIntegrationSettingsInput{
			IntegrationID:    integrationToUpdate.integrationID,
			IntegrationLabel: &newLabel,
			ScanIntervalMins: &newScanInterval,
		},
	}
	var result models.SourceIntegration
	require.NoError(t, genericapi.Invoke(lambdaClient, functionName, input, &result))
	assert.NotNil(t, result.AWSAccountID)
	assert.NotNil(t, result.CreatedAtTime)
	expected := models.SourceIntegration{
		SourceIntegrationMetadata: &models.SourceIntegrationMetadata{
			AWSAccountID:     result.AWSAccountID,
			CreatedAtTime:    result.CreatedAtTime,
			CreatedBy:        result.CreatedBy,
			IntegrationID:    integrationToUpdate.integrationID,
			IntegrationLabel: &newLabel,
			IntegrationType:  aws.String("aws-scan"),
			ScanEnabled:      aws.Bool(true),
			ScanIntervalMins: aws.Int(180),
			S3Buckets:        []*string{},
			KmsKeys:          []*string{},
		},
		SourceIntegrationStatus:          nil,
		SourceIntegrationScanInformation: nil,
	}
	assert.Equal(t, expected, result)

	input = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{IntegrationType: aws.String("aws-scan")},
	}
	var output []*models.SourceIntegration

	err := genericapi.Invoke(lambdaClient, functionName, &input, &output)
	require.NoError(t, err)
	for _, integration := range output {
		if integration.IntegrationID != integrationToUpdate.integrationID {
			continue
		}

		require.NotNil(t, integration.SourceIntegrationMetadata.ScanIntervalMins)
		assert.Equal(t, newScanInterval, *integration.SourceIntegrationMetadata.ScanIntervalMins)

		require.NotNil(t, integration.SourceIntegrationMetadata.IntegrationLabel)
		assert.Equal(t, newLabel, *integration.SourceIntegrationMetadata.IntegrationLabel)

		// Ensure other fields still exist after update
		assert.NotNil(t, integration.ScanEnabled)
		assert.NotNil(t, integration.IntegrationType)
	}
}

func updateIntegrationLastScanStart(t *testing.T) {
	integrationToUpdate := generatedIntegrationIDs[1]
	scanStartTime := time.Now()
	status := "scanning"

	// Update the integration

	input := &models.LambdaInput{
		UpdateIntegrationLastScanStart: &models.UpdateIntegrationLastScanStartInput{
			IntegrationID:     integrationToUpdate.integrationID,
			LastScanStartTime: &scanStartTime,
			ScanStatus:        &status,
		},
	}
	require.NoError(t, genericapi.Invoke(lambdaClient, functionName, input, nil))

	// Get the updated Integration

	input = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{IntegrationType: aws.String("aws-scan")},
	}
	var output []*models.SourceIntegration

	err := genericapi.Invoke(lambdaClient, functionName, &input, &output)
	require.NoError(t, err)
	for _, integration := range output {
		if integration.IntegrationID != integrationToUpdate.integrationID {
			continue
		}
		assert.Equal(t, status, *integration.SourceIntegrationStatus.ScanStatus)
		assert.Equal(t, scanStartTime, *integration.SourceIntegrationScanInformation.LastScanEndTime)
	}
}

func updateIntegrationLastScanEnd(t *testing.T) {
	integrationToUpdate := generatedIntegrationIDs[1]
	scanEndTime := time.Now()
	status := "ok"

	input := &models.LambdaInput{
		UpdateIntegrationLastScanEnd: &models.UpdateIntegrationLastScanEndInput{
			EventStatus:     &status,
			IntegrationID:   integrationToUpdate.integrationID,
			LastScanEndTime: &scanEndTime,
			ScanStatus:      &status,
		},
	}
	require.NoError(t, genericapi.Invoke(lambdaClient, functionName, input, nil))

	input = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{IntegrationType: aws.String("aws-scan")},
	}
	var output []*models.SourceIntegration

	err := genericapi.Invoke(lambdaClient, functionName, &input, &output)
	require.NoError(t, err)
	for _, integration := range output {
		if integration.IntegrationID != integrationToUpdate.integrationID {
			continue
		}
		assert.Equal(t, status, *integration.SourceIntegrationStatus.ScanStatus)
		assert.Equal(t, scanEndTime, *integration.SourceIntegrationScanInformation.LastScanEndTime)
	}
}

func updateIntegrationLastScanEndWithError(t *testing.T) {
	integrationToUpdate := generatedIntegrationIDs[1]
	scanEndTime := time.Now()
	status := "error"
	errorMessage := "fake error"

	input := &models.LambdaInput{
		UpdateIntegrationLastScanEnd: &models.UpdateIntegrationLastScanEndInput{
			EventStatus:          &status,
			IntegrationID:        integrationToUpdate.integrationID,
			LastScanEndTime:      &scanEndTime,
			LastScanErrorMessage: &errorMessage,
			ScanStatus:           &status,
		},
	}
	require.NoError(t, genericapi.Invoke(lambdaClient, functionName, input, nil))

	input = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{IntegrationType: aws.String("aws-scan")},
	}
	var output []*models.SourceIntegration

	err := genericapi.Invoke(lambdaClient, functionName, &input, &output)
	require.NoError(t, err)
	for _, integration := range output {
		if integration.IntegrationID != integrationToUpdate.integrationID {
			continue
		}
		assert.Equal(t, status, *integration.SourceIntegrationStatus.ScanStatus)
		assert.Equal(t, scanEndTime, *integration.SourceIntegrationScanInformation.LastScanEndTime)
	}
}
