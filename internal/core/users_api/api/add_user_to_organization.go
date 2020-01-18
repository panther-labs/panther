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
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Adds a user to the panther-users table
func addUser(email *string) error {
	// Check if user is already mapped to an organization
	existingUser, err := userTable.Get(email)
	if existingUser != nil {
		return &genericapi.AlreadyExistsError{Message: "user already exists: " + *email}
	}

	// If it a does not exist error, that is expected so continue
	// If it is another error, then return the error
	if _, isMissing := err.(*genericapi.DoesNotExistError); !isMissing {
		return err
	}

	// Add user - org mapping
	return userTable.Put(&models.UserItem{ID: email})
}
