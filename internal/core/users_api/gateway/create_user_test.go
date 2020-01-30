package gateway

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
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/pkg/genericapi"
)

var testCreateUserInput = &CreateUserInput{
	GivenName:   aws.String("Joe"),
	FamilyName:  aws.String("Blow"),
	Email:       aws.String("joe.blow@toe.com"),
	PhoneNumber: aws.String("+11234567890"),
	UserPoolID:  aws.String("userPoolId"),
}

var testAdminCreateUserInput = &provider.AdminCreateUserInput{
	DesiredDeliveryMediums: []*string{aws.String("EMAIL")},
	ForceAliasCreation:     aws.Bool(false),
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
			Name:  aws.String("phone_number"),
			Value: testCreateUserInput.PhoneNumber,
		},
		{
			Name:  aws.String("email_verified"),
			Value: aws.String("true"),
		},
	},
	Username:   testCreateUserInput.Email,
	UserPoolId: testCreateUserInput.UserPoolID,
}

func TestCreateUser(t *testing.T) {
	testUserID := aws.String("bc010600-b2d6-4a8d-92ac-d4f8bd209766")
	mockCognitoClient := &MockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	mockCognitoClient.On(
		"AdminCreateUser", testAdminCreateUserInput).Return(&provider.AdminCreateUserOutput{
		User: &provider.UserType{
			Username: testUserID,
		},
	}, nil)

	id, err := gw.CreateUser(testCreateUserInput)

	assert.Equal(t, id, testUserID)
	assert.NoError(t, err)
	mockCognitoClient.AssertExpectations(t)
}

func TestCreateUserFailed(t *testing.T) {
	mockCognitoClient := &MockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	mockCognitoClient.On("AdminCreateUser", testAdminCreateUserInput).Return(
		&provider.AdminCreateUserOutput{}, &genericapi.AWSError{})

	id, err := gw.CreateUser(testCreateUserInput)

	assert.Nil(t, id)
	assert.Error(t, err)
	mockCognitoClient.AssertExpectations(t)
}
