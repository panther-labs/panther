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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

func (g *UsersGateway) GetUser(id *string) (*models.User, error) {
	get, err := g.userPoolClient.AdminGetUser(
		&provider.AdminGetUserInput{Username: id, UserPoolId: g.userPoolID})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == provider.ErrCodeUserNotFoundException {
			return nil, &genericapi.DoesNotExistError{Message: "userID=" + *id + " does not exist"}
		}
		return nil, &genericapi.AWSError{Method: "cognito.AdminGetUser", Err: err}
	}

	return toUser(get.UserCreateDate, get.Username, get.UserStatus, get.UserAttributes), nil
}

// Convert Cognito attributes to User struct
func toUser(createdAt *time.Time, username, status *string, attrs []*provider.AttributeType) *models.User {
	user := models.User{
		CreatedAt: aws.Int64(createdAt.Unix()),
		ID:        username,
		Status:    status,
	}

	for _, attribute := range attrs {
		switch *attribute.Name {
		case "email":
			user.Email = attribute.Value
		case "family_name":
			user.FamilyName = attribute.Value
		case "given_name":
			user.GivenName = attribute.Value
		}
	}

	return &user
}
