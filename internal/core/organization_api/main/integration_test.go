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
	org             *models.Organization
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

	// Test endpoints against the non-existent organization (setup failed)
	t.Run("Empty", func(t *testing.T) {
		t.Run("GetOrgDeleted", getOrgDeleted)
		t.Run("UpdateOrgDeleted", updateOrgDeleted)
	})

	t.Run("Create", func(t *testing.T) {
		t.Run("CreateOrgInvalid", createOrgInvalid)
		t.Run("CreateOrg", createOrg)
	})
	if t.Failed() {
		return
	}

	t.Run("Read", func(t *testing.T) {
		t.Run("GetOrg", getOrg)
	})
	t.Run("Update", func(t *testing.T) {
		t.Run("UpdateOrg", updateOrg)
		t.Run("CompleteAction", completeAction)
	})
	if t.Failed() {
		return
	}
}

// ********** Subtests **********

func createOrgInvalid(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{CreateOrganization: &models.CreateOrganizationInput{
		DisplayName:          aws.String("panther-labs"),
		Email:                aws.String("runpanther.io"),
		AlertReportFrequency: aws.String("P1W"),
	}}
	err := genericapi.Invoke(lambdaClient, orgAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("CreateOrganization failed: invalid input: " +
			"Key: 'LambdaInput.CreateOrganization.Email' Error:" +
			"Field validation for 'Email' failed on the 'email' tag"),
		ErrorType:    aws.String("InvalidInputError"),
		FunctionName: orgAPI,
	}
	assert.Equal(t, expected, err)
}

func createOrg(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{CreateOrganization: &models.CreateOrganizationInput{
		AlertReportFrequency: aws.String("P1W"),
		AwsConfig: &models.AwsConfig{
			UserPoolID:     aws.String("userPool"),
			AppClientID:    aws.String("appClient"),
			IdentityPoolID: aws.String("identityPool"),
		},
		DisplayName: aws.String("panther-org-api-integration-test"),
		Email:       aws.String("eng@runpanther.io"),
		Phone:       aws.String("111-222-3333"),
	}}
	var output models.CreateOrganizationOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))
	org = output.Organization

	assert.NotNil(t, org.CreatedAt)
	expected := &models.Organization{
		AlertReportFrequency:  input.CreateOrganization.AlertReportFrequency,
		AwsConfig:             input.CreateOrganization.AwsConfig,
		CompletedActions:      []*string{},
		CreatedAt:             org.CreatedAt,
		DisplayName:           input.CreateOrganization.DisplayName,
		Email:                 input.CreateOrganization.Email,
		ErrorReportingConsent: nil,
		Phone:                 input.CreateOrganization.Phone,
	}
	assert.Equal(t, expected, org)
}

func getTest(t *testing.T) {
	input := models.LambdaInput{GetOrganization: &models.GetOrganizationInput{}}
	var output models.GetOrganizationOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))

	expected := models.GetOrganizationOutput{Organization: org}
	require.Equal(t, expected, output)
}

func getOrg(t *testing.T) {
	t.Parallel()
	getTest(t)
}

func updateOrg(t *testing.T) {
	input := models.LambdaInput{UpdateOrganization: &models.UpdateOrganizationInput{
		CreateOrganizationInput: models.CreateOrganizationInput{
			AlertReportFrequency: aws.String("P1D"),
			AwsConfig: &models.AwsConfig{
				UserPoolID:     aws.String("userPool"),
				AppClientID:    aws.String("appClient"),
				IdentityPoolID: aws.String("identityPool"),
			},
			DisplayName:           aws.String("panther-org-api-integration-test-update"),
			Email:                 aws.String("eng-update@runpanther.io"),
			ErrorReportingConsent: aws.Bool(true),
			Phone:                 aws.String("111-222-3456"),
		},
	}}
	var output models.UpdateOrganizationOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))

	expected := models.UpdateOrganizationOutput{
		Organization: &models.Organization{
			CompletedActions:      org.CompletedActions,
			CreatedAt:             org.CreatedAt,
			AlertReportFrequency:  input.UpdateOrganization.AlertReportFrequency,
			AwsConfig:             input.UpdateOrganization.AwsConfig,
			DisplayName:           input.UpdateOrganization.DisplayName,
			Email:                 input.UpdateOrganization.Email,
			ErrorReportingConsent: input.UpdateOrganization.ErrorReportingConsent,
			Phone:                 input.UpdateOrganization.Phone,
		},
	}
	require.Equal(t, expected, output)
	org = output.Organization
	getTest(t)
}

func completeAction(t *testing.T) {
	action := models.VisitedOnboardingFlow
	input := models.LambdaInput{CompleteAction: &models.CompleteActionInput{
		CompletedActions: []*models.Action{&action},
	}}
	var output models.CompleteActionOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, orgAPI, &input, &output))

	expected := models.CompleteActionOutput{
		CompletedActions: []*models.Action{&action},
	}
	assert.Equal(t, expected, output)
	org.CompletedActions = output.CompletedActions

	getTest(t) // verify update
}

func getOrgDeleted(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{GetOrganization: &models.GetOrganizationInput{}}
	err := genericapi.Invoke(lambdaClient, orgAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("GetOrganization failed: does not exist: "),
		ErrorType:    aws.String("DoesNotExistError"),
		FunctionName: orgAPI,
	}
	assert.Equal(t, expected, err)
}

func updateOrgDeleted(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{UpdateOrganization: &models.UpdateOrganizationInput{
		CreateOrganizationInput: models.CreateOrganizationInput{
			DisplayName: aws.String("a new name"),
			Email:       aws.String("eng-update@runpanther.io"),
		},
	}}
	err := genericapi.Invoke(lambdaClient, orgAPI, &input, nil)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("UpdateOrganization failed: does not exist: "),
		ErrorType:    aws.String("DoesNotExistError"),
		FunctionName: orgAPI,
	}
	assert.Equal(t, expected, err)
}
