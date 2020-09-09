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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// CreateUser creates a new user with specified attributes and sends out an email invitation.
func (g *UsersGateway) CreateUser(input *models.InviteUserInput) (*models.User, error) {
	zap.L().Info("creating new user in cognito", zap.Any("input", input))
	output, err := g.userPoolClient.AdminCreateUser(&provider.AdminCreateUserInput{
		DesiredDeliveryMediums: []*string{aws.String("EMAIL")},
		MessageAction:          input.MessageAction,
		UserAttributes:         userAttributes(input.GivenName, input.FamilyName, input.Email),
		// Cognito is case-sensitive for emails - it will allow multiple users with the same email
		// address if they have different casing. For that reason, we lowercase the email here.
		Username:   aws.String(strings.ToLower(*input.Email)),
		UserPoolId: g.userPoolID,
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "cognito.AdminCreateUser", Err: err}
	}

	u := output.User
	return toUser(u.UserCreateDate, u.Username, u.UserStatus, u.Attributes), nil
}

// Convert user metadata to Cognito attribute types.
func userAttributes(first, last, email *string) []*provider.AttributeType {
	var result []*provider.AttributeType

	if first != nil {
		result = append(result, &provider.AttributeType{
			Name:  aws.String("given_name"),
			Value: first,
		})
	}

	if last != nil {
		result = append(result, &provider.AttributeType{
			Name:  aws.String("family_name"),
			Value: last,
		})
	}

	if email != nil {
		result = append(result,
			&provider.AttributeType{
				Name:  aws.String("email"),
				Value: aws.String(strings.ToLower(*email)),
			},
			&provider.AttributeType{
				Name:  aws.String("email_verified"),
				Value: aws.String("true"),
			},
		)
	}

	return result
}
