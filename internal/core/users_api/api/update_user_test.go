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

type mockGatewayUpdateUserClient struct {
	gateway.API
	updateErr bool
}

func (m *mockGatewayUpdateUserClient) GetUser(id *string) (*models.User, error) {
	return &models.User{
		ID: id,
	}, nil
}

func (m *mockGatewayUpdateUserClient) UpdateUser(*models.UpdateUserInput) error {
	if m.updateErr {
		return &genericapi.AWSError{}
	}
	return nil
}

func TestUpdateUserGatewayErr(t *testing.T) {
	userGateway = &mockGatewayUpdateUserClient{updateErr: true}
	input := &models.UpdateUserInput{
		GivenName: aws.String("Richie"),
		ID:        aws.String("user123"),
	}
	result, err := (API{}).UpdateUser(input)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestUpdateUserHandle(t *testing.T) {
	userGateway = &mockGatewayUpdateUserClient{}
	input := &models.UpdateUserInput{
		GivenName: aws.String("Richie"),
		ID:        aws.String("user123"),
	}
	result, err := (API{}).UpdateUser(input)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
