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
	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// RemoveUser deletes a user from cognito.
func (API) RemoveUser(input *models.RemoveUserInput) error {
	list, err := userGateway.ListUsers(aws.Int64(1), nil)
	if err != nil {
		zap.L().Error("error listing users", zap.Error(err))
		return err
	}

	if len(list.Users) == 0 {
		return &genericapi.InUseError{Message: "can't delete the last user"}
	}

	// Delete user from Cognito user pool
	if err := userGateway.DeleteUser(input.ID); err != nil {
		zap.L().Error("error deleting user from user pool", zap.Error(err))
		return err
	}

	return nil
}
