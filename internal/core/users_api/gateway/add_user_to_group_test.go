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

var testAddUserToGroupInput = &provider.AdminAddUserToGroupInput{
	GroupName:  aws.String("Admin"),
	Username:   aws.String("bc010600-b2d6-4a8d-92ac-d4f8bd209766"),
	UserPoolId: aws.String("us-west-2_ZlG7Ldp1K"),
}

func TestAddUserToGroup(t *testing.T) {
	mockCognitoClient := &MockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	mockCognitoClient.On(
		"AdminAddUserToGroup", testAddUserToGroupInput).Return(&provider.AdminAddUserToGroupOutput{}, nil)

	assert.NoError(t, gw.AddUserToGroup(
		testAddUserToGroupInput.Username,
		testAddUserToGroupInput.GroupName,
		testAddUserToGroupInput.UserPoolId,
	))
	mockCognitoClient.AssertExpectations(t)
}

func TestAddUserToGroupFailure(t *testing.T) {
	mockCognitoClient := &MockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	mockCognitoClient.On("AdminAddUserToGroup", testAddUserToGroupInput).Return(
		&provider.AdminAddUserToGroupOutput{}, &genericapi.AWSError{})

	assert.Error(t, gw.AddUserToGroup(
		testAddUserToGroupInput.Username,
		testAddUserToGroupInput.GroupName,
		testAddUserToGroupInput.UserPoolId,
	))
	mockCognitoClient.AssertExpectations(t)
}
