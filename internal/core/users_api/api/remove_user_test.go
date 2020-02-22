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
	"github.com/panther-labs/panther/pkg/genericapi"
)

var removeUserInput = &models.RemoveUserInput{
	ID: aws.String("user123"),
}

func TestRemoveUserCognitoErr(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	// replace the global variables with our mock objects
	userGateway = mockGateway

	mockGateway.On("ListUsers").Return(make([]*models.User, 3), nil)
	mockGateway.On("DeleteUser", removeUserInput.ID).Return(&genericapi.AWSError{})

	err := (API{}).RemoveUser(removeUserInput)
	assert.Error(t, err)
	assert.IsType(t, err, &genericapi.AWSError{})

	mockGateway.AssertExpectations(t)
}

func TestRemoveLastUser(t *testing.T) {
	mockGateway := &gateway.MockUserGateway{}
	userGateway = mockGateway

	mockGateway.On("ListUsers").Return(make([]*models.User, 1), nil)

	err := (API{}).RemoveUser(removeUserInput)
	assert.Error(t, err)
	assert.IsType(t, err, &genericapi.InUseError{})
	mockGateway.AssertExpectations(t)
}

func TestRemoveUserHandle(t *testing.T) {
	mockGateway := &gateway.MockUserGateway{}
	userGateway = mockGateway

	mockGateway.On("ListUsers").Return(make([]*models.User, 3), nil)
	mockGateway.On("DeleteUser", removeUserInput.ID).Return(nil)

	assert.NoError(t, (API{}).RemoveUser(removeUserInput))
	mockGateway.AssertExpectations(t)
}
