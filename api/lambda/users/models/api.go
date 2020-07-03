package models

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

// User describes a Panther user
type User struct {
	CreatedAt  *int64  `json:"createdAt"`
	Email      *string `json:"email"`
	FamilyName *string `json:"familyName"`
	GivenName  *string `json:"givenName"`
	ID         *string `json:"id"`
	Status     *string `json:"status"`
}

// LambdaInput is the invocation event expected by the Lambda function.
//
// Exactly one action must be specified, see comments below for examples.
type LambdaInput struct {
	GetUser           *GetUserInput           `json:"getUser"`
	InviteUser        *InviteUserInput        `json:"inviteUser"`
	ListUsers         *ListUsersInput         `json:"listUsers"`
	RemoveUser        *RemoveUserInput        `json:"removeUser"`
	ResetUserPassword *ResetUserPasswordInput `json:"resetUserPassword"`
	UpdateUser        *UpdateUserInput        `json:"updateUser"`
}

// GetUserInput retrieves a user's information based on id.
//
// Example:
// {
//     "getUser": {
//         "id": "8304cc90-750d-4b8f-9a63-b90a4543c707"
//     }
// }
type GetUserInput struct {
	ID *string `json:"id" validate:"required,uuid4"`
}

// GetUserOutput returns the Panther user details.
//
// Example:
// {
//     "createdAt": 1583378248,
//     "email": "panther@example.com",
//     "familyName": "byers",
//     "givenName": "austin",
//     "id": "8304cc90-750d-4b8f-9a63-b90a4543c707",
//     "status": "FORCE_CHANGE_PASSWORD"
// }
type GetUserOutput = User

// InviteUserInput creates a new user with minimal permissions and sends them an invite.
type InviteUserInput struct {
	// Which Panther user is making this request?
	RequesterID *string `json:"requesterId" validate:"required,uuid4"`

	GivenName  *string `json:"givenName" validate:"required,min=1,excludesall='<>&\""`
	FamilyName *string `json:"familyName" validate:"required,min=1,excludesall='<>&\""`
	Email      *string `json:"email" validate:"required,email"`

	// RESEND or SUPPRESS the invitation message
	MessageAction *string `json:"messageAction" validate:"omitempty,oneof=RESEND SUPPRESS"`
}

// InviteUserOutput returns the new user details.
type InviteUserOutput = User

// ListUsersInput lists all users in Panther.
//
// Example:
// {
//     "listUsers": {
//         "contains": "austin"
//     }
// }
type ListUsersInput struct {
	// FILTERING (filters are combined with logical AND)
	// Show only users whose name or email contains this substring (case-insensitive)
	Contains *string `json:"contains"`

	// Show only users with this Cognito status
	Status *string `json:"status"`

	// SORTING
	// By default, sort by email ascending
	SortBy  *string `json:"sortBy" validate:"omitempty,oneof=email firstName lastName createdAt"`
	SortDir *string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`
}

// ListUsersOutput returns all matching users.
//
// {
//     "users": [
//         {
//             "createdAt": 1583378248,
//             "email": "austin.byers@runpanther.io",
//             "familyName": "byers",
//             "givenName": "austin",
//             "id": "8304cc90-750d-4b8f-9a63-b90a4543c707",
//             "status": "FORCE_CHANGE_PASSWORD"
//         }
//    ]
// }
type ListUsersOutput struct {
	Users []User `json:"users"`
}

// RemoveUserInput deletes a user.
//
// This will fail if the user is the only one with UserModify permissions.
type RemoveUserInput struct {
	// Which Panther user is making this request?
	RequesterID *string `json:"requesterId" validate:"required,uuid4"`

	ID *string `json:"id" validate:"required,uuid4"`
}

// RemoveUserOutput returns the ID of the deleted user.
type RemoveUserOutput struct {
	ID *string `json:"id"`
}

// ResetUserPasswordInput resets the password for a user.
type ResetUserPasswordInput struct {
	// Which Panther user is making this request?
	RequesterID *string `json:"requesterId" validate:"required,uuid4"`

	ID *string `json:"id" validate:"required,uuid4"`
}

// ResetUserPasswordOutput returns the ID of the reset user.
type ResetUserPasswordOutput struct {
	ID *string `json:"id"`
}

// UpdateUserInput updates user details.
type UpdateUserInput struct {
	// Which Panther user is making this request?
	RequesterID *string `json:"requesterId" validate:"required,uuid4"`

	ID *string `json:"id" validate:"required,uuid4"`

	// At least one of the following must be specified:
	GivenName  *string `json:"givenName" validate:"omitempty,min=1,excludesall='<>&\""`
	FamilyName *string `json:"familyName" validate:"omitempty,min=1,excludesall='<>&\""`
	Email      *string `json:"email" validate:"omitempty,min=1"`
}

// UpdateUserOutput returns the new Panther user details.
type UpdateUserOutput = User
