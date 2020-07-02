package api

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/core/users_api/cognito"
)

var inviteInput = &models.InviteUserInput{
	RequesterID: aws.String(systemUserID),
	GivenName:   aws.String("Joe"),
	Email:       aws.String("joe.blow@panther.io"),
	FamilyName:  aws.String("Blow"),
}
var userID = aws.String("1234-5678-9012")

func TestInviteUser(t *testing.T) {
	mockGateway := &cognito.MockUserGateway{}
	userGateway = mockGateway

	mockGateway.On("CreateUser", inviteInput).Return(&models.User{ID: userID}, nil)

	// call the code we are testing
	result, err := (API{}).InviteUser(inviteInput)

	// assert that the expectations were met
	require.NoError(t, err)
	mockGateway.AssertExpectations(t)
	assert.Equal(t, userID, result.ID)
}
