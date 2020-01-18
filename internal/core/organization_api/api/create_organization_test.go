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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/internal/core/organization_api/table"
)

type mockTable struct {
	table.API
	mock.Mock
}

func (m *mockTable) Put(input *models.Organization) error {
	args := m.Called(input)
	return args.Error(0)
}

func TestCreateOrganizationDynamoError(t *testing.T) {
	m := &mockTable{}
	orgTable = m

	// mock dynamo put
	m.On("Put", mock.Anything).Return(errors.New(""))

	result, err := (API{}).CreateOrganization(&models.CreateOrganizationInput{})
	m.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestCreateOrganization(t *testing.T) {
	m := &mockTable{}
	orgTable = m

	input := &models.CreateOrganizationInput{
		AlertReportFrequency: aws.String("P1W"),
		AwsConfig: &models.AwsConfig{
			UserPoolID:     aws.String("userPool"),
			AppClientID:    aws.String("appClient"),
			IdentityPoolID: aws.String("identityPool"),
		},
		DisplayName: aws.String("panther-labs"),
		Email:       aws.String("contact@runpanther.io"),
		Phone:       aws.String("111-222-3333"),
		RemediationConfig: &models.RemediationConfig{
			AwsRemediationLambdaArn: aws.String("arn:aws:lambda:us-west-2:415773754570:function:aws-auto-remediation"),
		},
	}

	// mock Dynamo put
	m.On("Put", mock.Anything).Return(nil)

	result, err := (API{}).CreateOrganization(input)
	require.NoError(t, err)
	m.AssertExpectations(t)

	expected := &models.CreateOrganizationOutput{
		Organization: &models.Organization{
			AlertReportFrequency: input.AlertReportFrequency,
			AwsConfig:            input.AwsConfig,
			CompletedActions:     nil,
			CreatedAt:            result.Organization.CreatedAt,
			DisplayName:          input.DisplayName,
			Email:                input.Email,
			Phone:                input.Phone,
			RemediationConfig:    input.RemediationConfig,
		},
	}
	assert.Equal(t, expected, result)
}

func TestCreateOrganizationSkipBilling(t *testing.T) {
	m := &mockTable{}
	orgTable = m

	input := &models.CreateOrganizationInput{
		AlertReportFrequency: aws.String("P1W"),
		AwsConfig: &models.AwsConfig{
			UserPoolID:     aws.String("userPool"),
			AppClientID:    aws.String("appClient"),
			IdentityPoolID: aws.String("identityPool"),
		},
		DisplayName: aws.String("panther-labs"),
		Email:       aws.String("contact@runpanther.io"),
		Phone:       aws.String("111-222-3333"),
		RemediationConfig: &models.RemediationConfig{
			AwsRemediationLambdaArn: aws.String("arn:aws:lambda:us-west-2:415773754570:function:aws-auto-remediation"),
		},
	}

	// mock Dynamo put
	m.On("Put", mock.Anything).Return(nil)

	result, err := (API{}).CreateOrganization(input)
	require.NoError(t, err)
	m.AssertExpectations(t)

	expected := &models.CreateOrganizationOutput{
		Organization: &models.Organization{
			AlertReportFrequency: input.AlertReportFrequency,
			AwsConfig:            input.AwsConfig,
			CompletedActions:     nil,
			CreatedAt:            result.Organization.CreatedAt,
			DisplayName:          input.DisplayName,
			Email:                input.Email,
			Phone:                input.Phone,
			RemediationConfig:    input.RemediationConfig,
		},
	}
	assert.Equal(t, expected, result)
}
