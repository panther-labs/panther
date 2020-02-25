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

type mockGatewayGetUserClient struct {
	gateway.API
	getUserGatewayErr bool
}

func (m *mockGatewayGetUserClient) GetUser(id *string) (*models.User, error) {
	if m.getUserGatewayErr {
		return nil, &genericapi.AWSError{}
	}
	return &models.User{
		GivenName:  aws.String("Joe"),
		FamilyName: aws.String("Blow"),
		ID:         id,
		Email:      aws.String("joe@blow.com"),
		CreatedAt:  aws.Int64(1545442826),
		Status:     aws.String("CONFIRMED"),
	}, nil
}

func TestGetUserGatewayErr(t *testing.T) {
	userGateway = &mockGatewayGetUserClient{getUserGatewayErr: true}
	result, err := (API{}).GetUser(&models.GetUserInput{})
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestGetUserHandle(t *testing.T) {
	userGateway = &mockGatewayGetUserClient{}
	result, err := (API{}).GetUser(&models.GetUserInput{})
	assert.NotNil(t, result)
	assert.NoError(t, err)
}
