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
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/core/users_api/gateway"
	users "github.com/panther-labs/panther/internal/core/users_api/table"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var removeUserInput = &models.RemoveUserInput{
	ID:         aws.String("user123"),
	UserPoolID: aws.String("fakePoolId"),
}

func TestRemoveUserGetErr(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	m := &users.MockTable{}
	// replace the global variables with our mock objects
	userGateway = mockGateway
	userTable = m

	mockGateway.On("GetUser", removeUserInput.ID, removeUserInput.UserPoolID).Return(&models.User{}, &genericapi.AWSError{})

	err := (API{}).RemoveUser(removeUserInput)
	assert.Error(t, err)
	assert.IsType(t, err, &genericapi.AWSError{})

	mockGateway.AssertExpectations(t)
	m.AssertExpectations(t)
	mockGateway.AssertNotCalled(t, "DeleteUser")
	m.AssertNotCalled(t, "Delete")
}

func TestRemoveUserCognitoErr(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	m := &users.MockTable{}
	// replace the global variables with our mock objects
	userGateway = mockGateway
	userTable = m

	mockGateway.On("GetUser", removeUserInput.ID, removeUserInput.UserPoolID).Return(&models.User{
		Email: aws.String("email@email.com"),
	}, nil)
	mockGateway.On("DeleteUser", removeUserInput.ID, removeUserInput.UserPoolID).Return(&genericapi.AWSError{})

	err := (API{}).RemoveUser(removeUserInput)
	assert.Error(t, err)
	assert.IsType(t, err, &genericapi.AWSError{})

	mockGateway.AssertExpectations(t)
	m.AssertExpectations(t)
	m.AssertNotCalled(t, "Delete")
}

func TestRemoveUserDynamoErr(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	m := &users.MockTable{}
	// replace the global variables with our mock objects
	userGateway = mockGateway
	userTable = m

	mockGateway.On("GetUser", removeUserInput.ID, removeUserInput.UserPoolID).Return(&models.User{
		Email: aws.String("email@email.com"),
	}, nil)
	mockGateway.On("DeleteUser", removeUserInput.ID, removeUserInput.UserPoolID).Return(nil)
	m.On("Delete", aws.String("email@email.com")).Return(&genericapi.AWSError{})

	err := (API{}).RemoveUser(removeUserInput)
	assert.Error(t, err)
	assert.IsType(t, err, &genericapi.AWSError{})

	mockGateway.AssertExpectations(t)
	m.AssertExpectations(t)
}

func TestRemoveUserHandle(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	m := &users.MockTable{}
	// replace the global variables with our mock objects
	userGateway = mockGateway
	userTable = m

	mockGateway.On("GetUser", removeUserInput.ID, removeUserInput.UserPoolID).Return(&models.User{
		Email: aws.String("email@email.com"),
	}, nil)
	mockGateway.On("DeleteUser", removeUserInput.ID, removeUserInput.UserPoolID).Return(nil)
	m.On("Delete", aws.String("email@email.com")).Return(nil)

	assert.NoError(t, (API{}).RemoveUser(removeUserInput))
	mockGateway.AssertExpectations(t)
	m.AssertExpectations(t)
}
