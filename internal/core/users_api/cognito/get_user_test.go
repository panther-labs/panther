package cognito

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/users/models"
)

var mockUserAttrs = []*provider.AttributeType{
	{
		Name:  aws.String("given_name"),
		Value: aws.String("Joe"),
	},
	{
		Name:  aws.String("family_name"),
		Value: aws.String("Blow"),
	},
	{
		Name:  aws.String("email"),
		Value: aws.String("joe.blow@example.com"),
	},
}

func TestGetUser(t *testing.T) {
	mockCognitoClient := &mockCognitoClient{}
	gw := &UsersGateway{userPoolClient: mockCognitoClient}

	input := &provider.AdminGetUserInput{
		Username:   aws.String("test-user"),
		UserPoolId: gw.userPoolID,
	}
	now := time.Now()
	output := &provider.AdminGetUserOutput{
		Enabled:              aws.Bool(true),
		UserAttributes:       mockUserAttrs,
		UserCreateDate:       &now,
		UserLastModifiedDate: &now,
		Username:             mockUserID,
		UserStatus:           aws.String("CONFIRMED"),
	}

	mockCognitoClient.On("AdminGetUser", input).Return(output, nil)

	result, err := gw.GetUser(aws.String("test-user"))
	expected := &models.User{
		CreatedAt:  aws.Int64(now.Unix()),
		Email:      aws.String("joe.blow@example.com"),
		FamilyName: aws.String("Blow"),
		GivenName:  aws.String("Joe"),
		ID:         mockUserID,
		Status:     aws.String("CONFIRMED"),
	}
	require.NoError(t, err)
	assert.Equal(t, expected, result)
	mockCognitoClient.AssertExpectations(t)
}
