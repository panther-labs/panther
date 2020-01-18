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
	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/core/users_api/gateway"
)

// UpdateUser modifies user attributes and roles.
func (API) UpdateUser(input *models.UpdateUserInput) error {
	// Update basic user attributes if needed.
	if input.GivenName != nil || input.FamilyName != nil || input.PhoneNumber != nil {
		if err := userGateway.UpdateUser(&gateway.UpdateUserInput{
			GivenName:   input.GivenName,
			FamilyName:  input.FamilyName,
			Email:       input.Email,
			PhoneNumber: input.PhoneNumber,
			ID:          input.ID,
			UserPoolID:  input.UserPoolID,
		}); err != nil {
			return err
		}
	}

	return nil
}
