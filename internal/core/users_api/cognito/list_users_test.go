package cognito

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/users/models"
)

func TestListUsers(t *testing.T) {
	mockCognitoClient := &mockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	input := &provider.ListUsersInput{UserPoolId: gw.userPoolID}
	now := time.Now()
	output := &provider.ListUsersOutput{
		Users: []*provider.UserType{
			{
				Attributes:           mockUserAttrs,
				Enabled:              aws.Bool(true),
				UserCreateDate:       &now,
				UserLastModifiedDate: &now,
				Username:             mockUserID,
				UserStatus:           aws.String("CONFIRMED"),
			},
		},
	}

	mockCognitoClient.On("ListUsersPages", input, mock.Anything).Return(output, nil)

	result, err := gw.ListUsers(&models.ListUsersInput{})
	require.NoError(t, err)

	expected := []*models.User{
		{
			CreatedAt:  aws.Int64(now.Unix()),
			Email:      aws.String("joe.blow@example.com"),
			FamilyName: aws.String("Blow"),
			GivenName:  aws.String("Joe"),
			ID:         mockUserID,
			Status:     aws.String("CONFIRMED"),
		},
	}
	assert.Equal(t, expected, result)
	mockCognitoClient.AssertExpectations(t)
}

func TestListUsersFilterByStatus(t *testing.T) {
	mockCognitoClient := &mockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	input := &provider.ListUsersInput{UserPoolId: gw.userPoolID}
	now := time.Now()
	output := &provider.ListUsersOutput{
		Users: []*provider.UserType{
			{
				Attributes:           mockUserAttrs,
				Enabled:              aws.Bool(true),
				UserCreateDate:       &now,
				UserLastModifiedDate: &now,
				Username:             mockUserID,
				UserStatus:           aws.String("CONFIRMED"),
			},
		},
	}

	mockCognitoClient.On("ListUsersPages", input, mock.Anything).Return(output, nil)

	result, err := gw.ListUsers(&models.ListUsersInput{Status: aws.String("CONFIRMED")})
	require.NoError(t, err)
	assert.Len(t, result, 1)
	mockCognitoClient.AssertExpectations(t)
}

func TestListUsersFilterByName(t *testing.T) {
	mockCognitoClient := &mockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	input := &provider.ListUsersInput{UserPoolId: gw.userPoolID}
	now := time.Now()
	output := &provider.ListUsersOutput{
		Users: []*provider.UserType{
			{
				Attributes:           mockUserAttrs,
				Enabled:              aws.Bool(true),
				UserCreateDate:       &now,
				UserLastModifiedDate: &now,
				Username:             mockUserID,
				UserStatus:           aws.String("CONFIRMED"),
			},
		},
	}

	mockCognitoClient.On("ListUsersPages", input, mock.Anything).Return(output, nil)

	// email matches
	result, err := gw.ListUsers(&models.ListUsersInput{Contains: aws.String("example.com")})
	require.NoError(t, err)
	assert.Len(t, result, 1)

	// name matches
	result, err = gw.ListUsers(&models.ListUsersInput{Contains: aws.String("joe")})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}
