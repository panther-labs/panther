package main

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
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	orgAPI    = "panther-organization-api"
	tableName = "panther-organization"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	lambdaClient    = lambda.New(awsSession)
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	os.Exit(m.Run())
}

// TestIntegrationAPI is the single integration test - invokes the live Lambda function.
func TestIntegrationAPI(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	require.NoError(t, testutils.ClearDynamoTable(awsSession, tableName))

	t.Run("GetSettingsEmpty", getSettingsEmpty)
	t.Run("UpdateSettings", updateSettings)
	t.Run("GetSettings", getSettings)
}

// ********** Subtests **********

func getSettingsEmpty(t *testing.T) {
	input := models.LambdaInput{GetSettings: &models.GetSettingsInput{}}
	var output models.GeneralSettings
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))

	var expected models.GeneralSettings
	assert.Equal(t, expected, output)
}

func updateSettings(t *testing.T) {
	// Update only email
	input := models.LambdaInput{
		UpdateSettings: &models.UpdateSettingsInput{
			Email: aws.String("test@example.com"),
		},
	}
	var output models.GeneralSettings
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))

	expected := models.GeneralSettings{Email: aws.String("test@example.com")}
	assert.Equal(t, expected, output)

	// Update other settings
	input = models.LambdaInput{
		UpdateSettings: &models.UpdateSettingsInput{
			DisplayName:           aws.String("panther-test"),
			ErrorReportingConsent: aws.Bool(true),
			AnalyticsConsent:      aws.Bool(true),
		},
	}
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))

	expected = models.GeneralSettings{
		DisplayName:           aws.String("panther-test"),
		Email:                 aws.String("test@example.com"),
		ErrorReportingConsent: aws.Bool(true),
		AnalyticsConsent:      aws.Bool(true),
	}
	assert.Equal(t, expected, output)
}

func getSettings(t *testing.T) {
	input := models.LambdaInput{GetSettings: &models.GetSettingsInput{}}
	var output models.GeneralSettings
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))

	expected := models.GeneralSettings{
		DisplayName:           aws.String("panther-test"),
		Email:                 aws.String("test@example.com"),
		ErrorReportingConsent: aws.Bool(true),
		AnalyticsConsent:      aws.Bool(true),
	}
	assert.Equal(t, expected, output)
}
