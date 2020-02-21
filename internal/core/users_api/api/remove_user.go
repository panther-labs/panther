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
)

// RemoveUser deletes a user from cognito.
func (API) RemoveUser(input *models.RemoveUserInput) error {
	// Delete user from Cognito user pool
	if err := userGateway.DeleteUser(input.ID); err != nil {
		zap.L().Error("error deleting user from user pool", zap.Error(err))
		return err
	}

	return nil
}
