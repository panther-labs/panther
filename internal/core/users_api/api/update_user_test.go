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

func TestUpdateUser(t *testing.T) {
	mockGateway := &cognito.MockUserGateway{}
	userGateway = mockGateway
	input := &models.UpdateUserInput{
		RequesterID: aws.String(systemUserID),
		ID:          aws.String("user-id"),
	}
	mockGateway.On("UpdateUser", input).Return(nil)
	mockGateway.On("GetUser", input.ID).Return(
		&models.User{ID: aws.String("user-id")}, nil)

	result, err := (API{}).UpdateUser(input)
	require.NoError(t, err)
	assert.NotNil(t, result)
}
