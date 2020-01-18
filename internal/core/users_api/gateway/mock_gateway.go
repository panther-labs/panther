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
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/users/models"
)

// MockUserGateway is a mocked object that implements the API interface
// It describes an object that the apis rely on.
type MockUserGateway struct {
	API
	mock.Mock
}

// The following methods implement the API interface
// and just record the activity, and returns what the Mock object tells it to.

// AddUserToGroup mocks AddUserToGroup for testing
func (m *MockUserGateway) AddUserToGroup(id *string, groupName *string, userPoolID *string) error {
	args := m.Called(id, groupName, userPoolID)
	return args.Error(0)
}

// CreateUser mocks CreateUser for testing
func (m *MockUserGateway) CreateUser(input *CreateUserInput) (*string, error) {
	args := m.Called(input)
	return args.Get(0).(*string), args.Error(1)
}

// GetUser mocks GetUser for testing
func (m *MockUserGateway) GetUser(id *string, userPoolID *string) (*models.User, error) {
	args := m.Called(id, userPoolID)
	return args.Get(0).(*models.User), args.Error(1)
}

// ListGroupsForUser mocks ListGroupsForUser for testing
func (m *MockUserGateway) ListGroupsForUser(id *string, userPoolID *string) ([]*models.Group, error) {
	args := m.Called(id, userPoolID)
	return args.Get(0).([]*models.Group), args.Error(1)
}

// ListUsers mocks ListUsers for testing
func (m *MockUserGateway) ListUsers(limit *int64, paginationToken *string, userPoolID *string) (*ListUsersOutput, error) {
	args := m.Called(limit, paginationToken, userPoolID)
	return args.Get(0).(*ListUsersOutput), args.Error(1)
}

// ResetUserPassword mocks ResetUserPassword for testing
func (m *MockUserGateway) ResetUserPassword(id *string, userPoolID *string) error {
	args := m.Called(id, userPoolID)
	return args.Error(0)
}

// UpdateUser mocks UpdateUser for testing
func (m *MockUserGateway) UpdateUser(input *UpdateUserInput) error {
	args := m.Called(input)
	return args.Error(0)
}
