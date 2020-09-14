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
	"github.com/aws/aws-sdk-go/aws/awserr"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateUser calls cognito to update a user with the specified attributes.
func (g *UsersGateway) UpdateUser(input *models.UpdateUserInput) error {
	cognitoInput := &provider.AdminUpdateUserAttributesInput{
		UserAttributes: userAttributes(input.GivenName, input.FamilyName, input.Email),
		UserPoolId:     g.userPoolID,
		Username:       input.ID,
	}
	if _, err := g.userPoolClient.AdminUpdateUserAttributes(cognitoInput); err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == provider.ErrCodeUserNotFoundException {
			return &genericapi.DoesNotExistError{Message: "userID=" + *input.ID + " does not exist"}
		}
		return &genericapi.AWSError{Method: "cognito.AdminUpdateUserAttributes", Err: err}
	}

	return nil
}
