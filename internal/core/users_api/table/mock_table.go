package users

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

// MockTable is a mocked object that implements the User Table API interface
type MockTable struct {
	API
	mock.Mock
}

// AddUserToOrganization mocks AddUserToOrganization for testing
func (m *MockTable) AddUserToOrganization(userItem *models.UserItem) error {
	args := m.Called(userItem)
	return args.Error(0)
}

// Delete mocks Delete for testing
func (m *MockTable) Delete(id *string) error {
	args := m.Called(id)
	return args.Error(0)
}

// Get mocks Get for testing
func (m *MockTable) Get(id *string) (*models.UserItem, error) {
	args := m.Called(id)
	return args.Get(0).(*models.UserItem), args.Error(1)
}

// Put mocks Put for testing
func (m *MockTable) Put(userItem *models.UserItem) error {
	args := m.Called(userItem)
	return args.Error(0)
}
