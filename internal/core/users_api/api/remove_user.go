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
	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// RemoveUser deletes a user from cognito.
func (API) RemoveUser(input *models.RemoveUserInput) (*models.RemoveUserOutput, error) {
	if err := validateRequester(input.RequesterID); err != nil {
		return nil, err
	}

	users, err := userGateway.ListUsers(&models.ListUsersInput{})
	if err != nil {
		return nil, err
	}

	if len(users) == 1 {
		return nil, &genericapi.InUseError{Message: "can't delete the last user"}
	}

	// Delete user from Cognito user pool
	if err := userGateway.DeleteUser(input.ID); err != nil {
		return nil, err
	}
	return &models.RemoveUserOutput{ID: input.ID}, nil
}
