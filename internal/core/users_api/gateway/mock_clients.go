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
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	providerI "github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/stretchr/testify/mock"
)

// MockCognitoClient can be passed as a mock object to unit tests
type MockCognitoClient struct {
	providerI.CognitoIdentityProviderAPI
	mock.Mock
}

// AdminAddUserToGroup mocks AdminAddUserToGroup for testing
func (m *MockCognitoClient) AdminAddUserToGroup(
	input *provider.AdminAddUserToGroupInput) (*provider.AdminAddUserToGroupOutput, error) {

	args := m.Called(input)
	return args.Get(0).(*provider.AdminAddUserToGroupOutput), args.Error(1)
}

// AdminCreateUser mocks AdminCreateUser for testing
func (m *MockCognitoClient) AdminCreateUser(
	input *provider.AdminCreateUserInput) (*provider.AdminCreateUserOutput, error) {

	args := m.Called(input)
	return args.Get(0).(*provider.AdminCreateUserOutput), args.Error(1)
}

// CreateGroup mocks CreateGroup for testing
func (m *MockCognitoClient) CreateGroup(
	input *provider.CreateGroupInput) (*provider.CreateGroupOutput, error) {

	args := m.Called(input)
	return args.Get(0).(*provider.CreateGroupOutput), args.Error(1)
}
