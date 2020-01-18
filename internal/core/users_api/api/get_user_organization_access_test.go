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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	organizationmodels "github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/api/lambda/users/models"
	users "github.com/panther-labs/panther/internal/core/users_api/table"
	"github.com/panther-labs/panther/pkg/genericapi"
)

func TestGetUserOrganizationAccessSuccess(t *testing.T) {
	m := &users.MockTable{}
	organizationAPI = "organizationAPI"
	userTable = m
	email := aws.String("joe@blow.com")
	m.On("Get", email).Return(&models.UserItem{
		ID: aws.String("user-123"),
	}, nil)

	ml := &mockLambdaClient{}
	lambdaClient = ml
	getOrgOutput := organizationmodels.GetOrganizationOutput{
		Organization: &organizationmodels.Organization{
			CreatedAt:            aws.String("time-123"),
			DisplayName:          aws.String("Initech"),
			Email:                aws.String("joe@blow.com"),
			AlertReportFrequency: aws.String("errday"),
			AwsConfig: &organizationmodels.AwsConfig{
				UserPoolID:     aws.String("userpool-123"),
				AppClientID:    aws.String("client-123"),
				IdentityPoolID: aws.String("identitypool-123"),
			},
		},
	}
	mockOrgLambdaResponsePayload, err := jsoniter.Marshal(getOrgOutput)
	require.NoError(t, err)
	mockOrgLambdaResponse := &lambda.InvokeOutput{Payload: mockOrgLambdaResponsePayload}
	expecteOrgLambdaPayload, err := jsoniter.Marshal(
		organizationmodels.LambdaInput{GetOrganization: &organizationmodels.GetOrganizationInput{}})
	require.NoError(t, err)
	expectedOrgLambdaInput := &lambda.InvokeInput{FunctionName: aws.String("organizationAPI"), Payload: expecteOrgLambdaPayload}
	ml.On("Invoke", expectedOrgLambdaInput).Return(mockOrgLambdaResponse, nil)

	result, err := (API{}).GetUserOrganizationAccess(&models.GetUserOrganizationAccessInput{
		Email: email,
	})
	assert.NotNil(t, result)
	assert.NoError(t, err)
}

func TestGetUserOrganizationAccessGetUserFailed(t *testing.T) {
	m := &users.MockTable{}
	organizationAPI = "organizationAPI"
	userTable = m
	email := aws.String("joe@blow.com")
	m.On("Get", email).Return(&models.UserItem{}, &genericapi.LambdaError{})

	result, err := (API{}).GetUserOrganizationAccess(&models.GetUserOrganizationAccessInput{
		Email: email,
	})
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestGetUserOrganizationAccessGetOrganizationsFailed(t *testing.T) {
	m := &users.MockTable{}
	organizationAPI = "organizationAPI"
	userTable = m
	email := aws.String("joe@blow.com")
	m.On("Get", email).Return(&models.UserItem{
		ID: aws.String("user-123"),
	}, nil)

	ml := &mockLambdaClient{}
	lambdaClient = ml
	getOrgOutput := organizationmodels.GetOrganizationOutput{}
	mockOrgLambdaResponsePayload, err := jsoniter.Marshal(getOrgOutput)
	require.NoError(t, err)
	mockOrgLambdaResponse := &lambda.InvokeOutput{Payload: mockOrgLambdaResponsePayload}
	expectedOrgLambdaPayload, err := jsoniter.Marshal(
		organizationmodels.LambdaInput{GetOrganization: &organizationmodels.GetOrganizationInput{}})
	require.NoError(t, err)
	expectedOrgLambdaInput := &lambda.InvokeInput{FunctionName: aws.String("organizationAPI"), Payload: expectedOrgLambdaPayload}
	ml.On("Invoke", expectedOrgLambdaInput).Return(mockOrgLambdaResponse, &genericapi.LambdaError{})

	result, err := (API{}).GetUserOrganizationAccess(&models.GetUserOrganizationAccessInput{
		Email: email,
	})
	assert.Nil(t, result)
	assert.Error(t, err)
}
