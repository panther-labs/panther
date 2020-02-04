package api

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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/core/users_api/gateway"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type mockGatewayListUsersClient struct {
	gateway.API
	listUserGatewayErr  bool
	listGroupGatewayErr bool
}

func (m *mockGatewayListUsersClient) ListUsers(
	limit *int64, paginationToken *string, userPoolID *string) (*gateway.ListUsersOutput, error) {

	if m.listUserGatewayErr {
		return nil, &genericapi.AWSError{}
	}

	return &gateway.ListUsersOutput{
		Users: []*models.User{
			{
				GivenName:   aws.String("Joe"),
				FamilyName:  aws.String("Blow"),
				ID:          aws.String("user123"),
				Email:       aws.String("joe@blow.com"),
				PhoneNumber: aws.String("+1234567890"),
				CreatedAt:   aws.Int64(1545442826),
				Status:      aws.String("CONFIRMED"),
			},
		},
		PaginationToken: paginationToken,
	}, nil
}

func (m *mockGatewayListUsersClient) ListGroupsForUser(*string, *string) ([]*models.Group, error) {
	if m.listGroupGatewayErr {
		return nil, &genericapi.AWSError{}
	}

	return []*models.Group{
		{
			Description: aws.String("Roles Description"),
			Name:        aws.String("Admins"),
		},
	}, nil
}

func TestListUsersGatewayErr(t *testing.T) {
	userGateway = &mockGatewayListUsersClient{listUserGatewayErr: true}
	result, err := (API{}).ListUsers(&models.ListUsersInput{
		UserPoolID:      aws.String("fakePoolId"),
		Limit:           aws.Int64(10),
		PaginationToken: aws.String("paginationToken"),
	})
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestListGroupsForUserGatewayErr(t *testing.T) {
	userGateway = &mockGatewayListUsersClient{listGroupGatewayErr: true}
	result, err := (API{}).ListUsers(&models.ListUsersInput{
		UserPoolID:      aws.String("fakePoolId"),
		Limit:           aws.Int64(10),
		PaginationToken: aws.String("paginationToken"),
	})
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestListUsersHandle(t *testing.T) {
	userGateway = &mockGatewayListUsersClient{}
	result, err := (API{}).ListUsers(&models.ListUsersInput{
		UserPoolID:      aws.String("fakePoolId"),
		Limit:           aws.Int64(10),
		PaginationToken: aws.String("paginationToken"),
	})
	assert.NotNil(t, result)
	assert.NoError(t, err)
}
