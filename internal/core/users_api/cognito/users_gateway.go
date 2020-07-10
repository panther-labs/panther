package cognito

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	userPoolProvider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	userPoolProviderI "github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"

	"github.com/panther-labs/panther/api/lambda/users/models"
)

// API defines the interface for the user gateway which can be used for mocking.
type API interface {
	CreateUser(*models.InviteUserInput) (*models.User, error)
	DeleteUser(*string) error
	GetUser(*string) (*models.User, error)
	ListUsers(*models.ListUsersInput) ([]models.User, error)
	ResetUserPassword(*string) error
	UpdateUser(*models.UpdateUserInput) error
}

// UsersGateway encapsulates a service to Cognito Client.
type UsersGateway struct {
	userPoolClient userPoolProviderI.CognitoIdentityProviderAPI
	userPoolID     *string
}

// The UsersGateway must satisfy the API interface.
var _ API = (*UsersGateway)(nil)

// New creates a new CognitoIdentityProvider client which talks to the given user pool.
func New(sess *session.Session, userPoolID string) *UsersGateway {
	return &UsersGateway{
		userPoolClient: userPoolProvider.New(sess),
		userPoolID:     aws.String(userPoolID),
	}
}
