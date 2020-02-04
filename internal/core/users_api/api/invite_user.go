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
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/core/users_api/gateway"
)

// InviteUser adds a new user to the Cognito user pool.
func (API) InviteUser(input *models.InviteUserInput) (*models.InviteUserOutput, error) {
	// Add user to org mapping in dynamo
	if err := addUser(input.Email); err != nil {
		return nil, err
	}

	// Create user in Cognito
	id, err := userGateway.CreateUser(&gateway.CreateUserInput{
		GivenName:  input.GivenName,
		FamilyName: input.FamilyName,
		Email:      input.Email,
		UserPoolID: input.UserPoolID,
	})
	if err != nil {
		if deleteErr := userTable.Delete(input.Email); deleteErr != nil {
			zap.L().Error("error deleting user from dynamo after failed invitation", zap.Error(deleteErr))
		}
		return nil, err
	}

	if err = userGateway.AddUserToGroup(id, input.UserPoolID); err != nil {
		return nil, err
	}

	return &models.InviteUserOutput{ID: id}, nil
}
