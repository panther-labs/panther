package cognito

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var (
	mockUserID = aws.String("156b8cc0-45f3-409c-a49e-69af4a149e01")

	testCreateUserInput = &models.InviteUserInput{
		GivenName:  aws.String("Joe"),
		FamilyName: aws.String("Blow"),
		Email:      aws.String("joe.blow@toe.com"),
	}

	testAdminCreateUserInput = &provider.AdminCreateUserInput{
		DesiredDeliveryMediums: []*string{aws.String("EMAIL")},
		UserAttributes: []*provider.AttributeType{
			{
				Name:  aws.String("given_name"),
				Value: testCreateUserInput.GivenName,
			},
			{
				Name:  aws.String("family_name"),
				Value: testCreateUserInput.FamilyName,
			},
			{
				Name:  aws.String("email"),
				Value: testCreateUserInput.Email,
			},
			{
				Name:  aws.String("email_verified"),
				Value: aws.String("true"),
			},
		},
		Username: testCreateUserInput.Email,
	}
)

func TestCreateUserFailed(t *testing.T) {
	mockCognitoClient := &mockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	mockCognitoClient.On("AdminCreateUser", testAdminCreateUserInput).Return(
		(*provider.AdminCreateUserOutput)(nil), &genericapi.AWSError{})

	id, err := gw.CreateUser(testCreateUserInput)
	assert.Nil(t, id)
	assert.Error(t, err)
	mockCognitoClient.AssertExpectations(t)
}

func TestCreateUser(t *testing.T) {
	mockCognitoClient := &mockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	mockCognitoClient.On(
		"AdminCreateUser",
		testAdminCreateUserInput,
	).Return(
		&provider.AdminCreateUserOutput{
			User: &provider.UserType{
				UserCreateDate: aws.Time(time.Now()),
				Username:       mockUserID,
				UserStatus:     aws.String("FORCE_CHANGE_PASSWORD"),
			},
		},
		nil,
	)

	user, err := gw.CreateUser(testCreateUserInput)
	require.NoError(t, err)
	assert.Equal(t, mockUserID, user.ID)
	mockCognitoClient.AssertExpectations(t)
}
