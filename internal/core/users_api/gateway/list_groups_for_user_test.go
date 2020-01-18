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
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	providerI "github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/users/models"
)

type mockListGroupsForUserClient struct {
	providerI.CognitoIdentityProviderAPI
	serviceErr bool
}

func (m *mockListGroupsForUserClient) AdminListGroupsForUser(
	*provider.AdminListGroupsForUserInput) (*provider.AdminListGroupsForUserOutput, error) {

	if m.serviceErr {
		return nil, errors.New("cognito does not exist")
	}

	return &provider.AdminListGroupsForUserOutput{
		Groups: []*provider.GroupType{
			{
				CreationDate:     &time.Time{},
				Description:      aws.String("Roles Description"),
				GroupName:        aws.String("Admins"),
				LastModifiedDate: &time.Time{},
				Precedence:       aws.Int64(0),
				RoleArn:          aws.String("arn::1234567"),
				UserPoolId:       aws.String("Pool 123"),
			},
		},
	}, nil
}

func TestListGroupsForUser(t *testing.T) {
	gw := &UsersGateway{userPoolClient: &mockListGroupsForUserClient{}}
	result, err := gw.ListGroupsForUser(aws.String("user123"), aws.String("fakePoolId"))
	groups := []*models.Group{
		{
			Description: aws.String("Roles Description"),
			Name:        aws.String("Admins"),
		},
	}
	assert.Equal(t, groups, result)
	assert.NoError(t, err)
}

func TestListGroupsForUserFailed(t *testing.T) {
	gw := &UsersGateway{userPoolClient: &mockListGroupsForUserClient{serviceErr: true}}
	result, err := gw.ListGroupsForUser(aws.String("user123"), aws.String("fakePoolId"))
	assert.Nil(t, result)
	assert.Error(t, err)
}
