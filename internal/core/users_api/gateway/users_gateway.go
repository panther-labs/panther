package gateway

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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	cfnIface "github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	fedIdentityProvider "github.com/aws/aws-sdk-go/service/cognitoidentity"
	fedIdentityProviderI "github.com/aws/aws-sdk-go/service/cognitoidentity/cognitoidentityiface"
	userPoolProvider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	userPoolProviderI "github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/panther-labs/panther/api/lambda/users/models"
)

// API defines the interface for the user gateway which can be used for mocking.
type API interface {
	AddUserToGroup(id *string, groupName *string, userPoolID *string) error
	CreateUser(input *CreateUserInput) (*string, error)
	GetUser(id *string, userPoolID *string) (*models.User, error)
	ListGroupsForUser(id *string, userPoolID *string) ([]*models.Group, error)
	ListUsers(limit *int64, paginationToken *string, userPoolID *string) (*ListUsersOutput, error)
	ResetUserPassword(id *string, userPoolID *string) error
	UpdateUser(input *UpdateUserInput) error
}

// UsersGateway encapsulates a service to Cognito Client.
type UsersGateway struct {
	userPoolClient        userPoolProviderI.CognitoIdentityProviderAPI
	fedIdentityClient     fedIdentityProviderI.CognitoIdentityAPI
	iamService            IAMService
	cloudFormationService cfnIface.CloudFormationAPI
}

// The UsersGateway must satisfy the API interface.
var _ API = (*UsersGateway)(nil)

// IAMService is an interface for unit testing.  It must be satisfied by UsersGateway.iamService.
type IAMService interface {
	GetRole(*iam.GetRoleInput) (*iam.GetRoleOutput, error)
	UpdateAssumeRolePolicy(input *iam.UpdateAssumeRolePolicyInput) (*iam.UpdateAssumeRolePolicyOutput, error)
}

// New creates a new CognitoIdentityProvider client which talks to the given user pool.
func New(sess *session.Session) *UsersGateway {
	return &UsersGateway{
		userPoolClient:        userPoolProvider.New(sess),
		fedIdentityClient:     fedIdentityProvider.New(sess),
		iamService:            iam.New(sess),
		cloudFormationService: cloudformation.New(sess),
	}
}
