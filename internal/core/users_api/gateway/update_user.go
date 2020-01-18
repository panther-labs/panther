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

	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateUserInput is input for UpdateUser request
type UpdateUserInput struct {
	ID          *string `json:"id"`
	GivenName   *string `json:"givenName"`
	FamilyName  *string `json:"familyName"`
	Email       *string `json:"email"`
	PhoneNumber *string `json:"phoneNumber"`
	UserPoolID  *string `json:"userPoolId"`
}

// Create a AdminUpdateUserAttributesInput from the UpdateUserInput.
func (g *UsersGateway) updateInputMapping(
	input *UpdateUserInput) *provider.AdminUpdateUserAttributesInput {

	var userAttrs []*provider.AttributeType

	if input.GivenName != nil {
		userAttrs = append(userAttrs, &provider.AttributeType{
			Name:  aws.String("given_name"),
			Value: input.GivenName,
		})
	}

	if input.FamilyName != nil {
		userAttrs = append(userAttrs, &provider.AttributeType{
			Name:  aws.String("family_name"),
			Value: input.FamilyName,
		})
	}

	if input.Email != nil {
		userAttrs = append(userAttrs, &provider.AttributeType{
			Name:  aws.String("email"),
			Value: input.Email,
		})
		userAttrs = append(userAttrs, &provider.AttributeType{
			Name:  aws.String("email_verified"),
			Value: aws.String("true"),
		})
	}

	if input.PhoneNumber != nil {
		userAttrs = append(userAttrs, &provider.AttributeType{
			Name:  aws.String("phone_number"),
			Value: input.PhoneNumber,
		})
	}

	return &provider.AdminUpdateUserAttributesInput{
		UserAttributes: userAttrs,
		Username:       input.ID,
		UserPoolId:     input.UserPoolID,
	}
}

// UpdateUser calls cognito api and update a user with specified attributes
func (g *UsersGateway) UpdateUser(input *UpdateUserInput) error {
	cognitoInput := g.updateInputMapping(input)
	if _, err := g.userPoolClient.AdminUpdateUserAttributes(cognitoInput); err != nil {
		return &genericapi.AWSError{Method: "cognito.AdminUpdateUserAttributes", Err: err}
	}
	return nil
}
