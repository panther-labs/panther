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

// InviteUser adds a new user to the Cognito user pool.
func (API) InviteUser(input *models.InviteUserInput) (*models.InviteUserOutput, error) {
	if err := validateRequester(input.RequesterID); err != nil {
		return nil, err
	}
	return userGateway.CreateUser(input)
}

// Returns an error if the user who initiated the request could not be validated.
//
// A user which has been deleted may still have a valid access token for up to 1h.
// To prevent a malicious deleted user from establishing persistence, user management operations
// explicitly verify the requester's identity on every request.
//
// TODO - replace this with a more holistic approach in a unified API across all of Panther
func validateRequester(requesterID *string) error {
	// When a user is making the request, the requesterID is set by AppSync based on the login token,
	// so it is a trustworthy proof. When the backend is making the request directly (e.g. first deployment),
	// it will pass the systemID instead of a real userID.
	// Users cannot spoof this value because they cannot talk to this (or any) Lambda function directly.
	if *requesterID == systemUserID {
		return nil
	}

	if _, err := userGateway.GetUser(requesterID); err != nil {
		return &genericapi.InvalidInputError{Message: "failed to validate the user making the request: " + err.Error()}
	}
	return nil
}
