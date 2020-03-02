package models

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

// LambdaInput is the invocation event expected by the Lambda function.
//
// Exactly one action must be specified.
type LambdaInput struct {
	GetUser           *GetUserInput           `json:"getUser"`
	InviteUser        *InviteUserInput        `json:"inviteUser"`
	ListUsers         *ListUsersInput         `json:"listUsers"`
	RemoveUser        *RemoveUserInput        `json:"removeUser"`
	ResetUserPassword *ResetUserPasswordInput `json:"resetUserPassword"`
	UpdateUser        *UpdateUserInput        `json:"updateUser"`
}

// GetUserInput retrieves a user's information based on id.
type GetUserInput struct {
	ID *string `json:"id" validate:"required,uuid4"`
}

// GetUserOutput returns the Panther user details.
type GetUserOutput = User

// InviteUserInput creates a new user with minimal permissions and sends them an invite.
type InviteUserInput struct {
	GivenName  *string `json:"givenName" validate:"required,min=1"`
	FamilyName *string `json:"familyName" validate:"required,min=1"`
	Email      *string `json:"email" validate:"required,email"`
}

// InviteUserOutput returns the randomly generated user id.
type InviteUserOutput struct {
	ID *string `json:"id"`
}

// ListUsersInput lists all users in Panther.
type ListUsersInput struct{}

// ListUsersOutput returns a page of users.
type ListUsersOutput struct {
	Users []*User `json:"users"`
}

// RemoveUserInput deletes a user.
type RemoveUserInput struct {
	ID *string `json:"id" validate:"required,uuid4"`
}

// ResetUserPasswordInput resets the password for a user.
type ResetUserPasswordInput struct {
	ID *string `json:"id" validate:"required,uuid4"`
}

// UpdateUserInput updates user details.
type UpdateUserInput struct {
	ID *string `json:"id" validate:"required,uuid4"`

	// At least one of the following must be specified:
	GivenName  *string `json:"givenName" validate:"omitempty,min=1"`
	FamilyName *string `json:"familyName" validate:"omitempty,min=1"`
	Email      *string `json:"email" validate:"omitempty,min=1"`
}

// UpdateUserOutput returns the new Panther user details.
type UpdateUserOutput = User
