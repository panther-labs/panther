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
	"github.com/aws/aws-sdk-go/aws"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ListUsersOutput is output type for ListUsers
type ListUsersOutput struct {
	Users           []*models.User
	PaginationToken *string
}

func mapCognitoUserTypeToUser(u *provider.UserType) *models.User {
	user := models.User{
		CreatedAt: aws.Int64(u.UserCreateDate.Unix()),
		ID:        u.Username,
		Status:    u.UserStatus,
	}

	for _, attribute := range u.Attributes {
		switch *attribute.Name {
		case "email":
			user.Email = attribute.Value
		case "given_name":
			user.GivenName = attribute.Value
		case "family_name":
			user.FamilyName = attribute.Value
		}
	}

	return &user
}

// ListUsers calls cognito api to list users that belongs to a user pool
func (g *UsersGateway) ListUsers(limit *int64, paginationToken *string) (*ListUsersOutput, error) {
	usersOutput, err := g.userPoolClient.ListUsers(&provider.ListUsersInput{
		Limit:           limit,
		PaginationToken: paginationToken,
		UserPoolId:      &userPoolID,
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "cognito.ListUsers", Err: err}
	}

	users := make([]*models.User, len(usersOutput.Users))
	for i, uo := range usersOutput.Users {
		users[i] = mapCognitoUserTypeToUser(uo)
	}
	return &ListUsersOutput{Users: users, PaginationToken: usersOutput.PaginationToken}, nil
}
