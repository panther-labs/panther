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

var input = &models.InviteUserInput{
	GivenName:  aws.String("Joe"),
	Email:      aws.String("joe.blow@panther.io"),
	FamilyName: aws.String("Blow"),
}
var userID = aws.String("1234-5678-9012")

func TestInviteUserCreateErr(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	// replace the global variables with our mock objects
	userGateway = mockGateway

	// setup gateway expectations
	mockGateway.On("CreateUser", &gateway.CreateUserInput{
		GivenName:  input.GivenName,
		FamilyName: input.FamilyName,
		Email:      input.Email,
	}).Return(aws.String(""), &genericapi.AWSError{})

	// call the code we are testing
	result, err := (API{}).InviteUser(input)

	// assert that the expectations were met
	mockGateway.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, err, &genericapi.AWSError{})
}

func TestInviteUserDeleteErr(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	// replace the global variables with our mock objects
	userGateway = mockGateway

	// setup expectations
	mockGateway.On("CreateUser", &gateway.CreateUserInput{
		GivenName:  input.GivenName,
		FamilyName: input.FamilyName,
		Email:      input.Email,
	}).Return(aws.String(""), &genericapi.AWSError{})

	// call the code we are testing
	result, err := (API{}).InviteUser(input)

	// assert that the expectations were met
	mockGateway.AssertExpectations(t)
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.IsType(t, err, &genericapi.AWSError{})
}

func TestInviteUserHandle(t *testing.T) {
	// create an instance of our test objects
	mockGateway := &gateway.MockUserGateway{}
	// replace the global variables with our mock objects
	userGateway = mockGateway

	// setup gateway expectations
	mockGateway.On("CreateUser", &gateway.CreateUserInput{
		GivenName:  input.GivenName,
		FamilyName: input.FamilyName,
		Email:      input.Email,
	}).Return(userID, nil)

	// call the code we are testing
	result, err := (API{}).InviteUser(input)

	// assert that the expectations were met
	mockGateway.AssertExpectations(t)
	assert.NotNil(t, result)
	assert.Equal(t, result, &models.InviteUserOutput{
		ID: userID,
	})
	assert.NoError(t, err)
}
