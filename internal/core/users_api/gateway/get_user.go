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

func mapGetUserOutputToPantherUser(u *provider.AdminGetUserOutput) *models.User {
	user := models.User{
		CreatedAt: aws.Int64(u.UserCreateDate.Unix()),
		ID:        u.Username,
		Status:    u.UserStatus,
	}

	for _, attribute := range u.UserAttributes {
		switch *attribute.Name {
		case "email":
			user.Email = attribute.Value
		case "phone_number":
			user.PhoneNumber = attribute.Value
		case "given_name":
			user.GivenName = attribute.Value
		case "family_name":
			user.FamilyName = attribute.Value
		}
	}

	return &user
}

// GetUser calls cognito api to get user info
func (g *UsersGateway) GetUser(id *string, userPoolID *string) (*models.User, error) {
	user, err := g.userPoolClient.AdminGetUser(&provider.AdminGetUserInput{
		Username:   id,
		UserPoolId: userPoolID,
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "cognito.AdminGetUser", Err: err}
	}
	return mapGetUserOutputToPantherUser(user), nil
}
