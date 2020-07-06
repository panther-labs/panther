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
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	providerI "github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/stretchr/testify/mock"
)

type mockCognitoClient struct {
	providerI.CognitoIdentityProviderAPI
	mock.Mock
}

func (m *mockCognitoClient) AdminCreateUser(input *provider.AdminCreateUserInput) (*provider.AdminCreateUserOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*provider.AdminCreateUserOutput), args.Error(1)
}

func (m *mockCognitoClient) AdminDeleteUser(input *provider.AdminDeleteUserInput) (*provider.AdminDeleteUserOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*provider.AdminDeleteUserOutput), args.Error(1)
}

func (m *mockCognitoClient) AdminGetUser(input *provider.AdminGetUserInput) (*provider.AdminGetUserOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*provider.AdminGetUserOutput), args.Error(1)
}

func (m *mockCognitoClient) AdminResetUserPassword(
	input *provider.AdminResetUserPasswordInput) (*provider.AdminResetUserPasswordOutput, error) {

	args := m.Called(input)
	return args.Get(0).(*provider.AdminResetUserPasswordOutput), args.Error(1)
}

func (m *mockCognitoClient) AdminUserGlobalSignOut(
	input *provider.AdminUserGlobalSignOutInput) (*provider.AdminUserGlobalSignOutOutput, error) {

	args := m.Called(input)
	return args.Get(0).(*provider.AdminUserGlobalSignOutOutput), args.Error(1)
}

func (m *mockCognitoClient) AdminUpdateUserAttributes(
	input *provider.AdminUpdateUserAttributesInput) (*provider.AdminUpdateUserAttributesOutput, error) {

	args := m.Called(input)
	return args.Get(0).(*provider.AdminUpdateUserAttributesOutput), args.Error(1)
}

// First return argument is what to pass to the pager
func (m *mockCognitoClient) ListUsersPages(
	input *provider.ListUsersInput,
	pager func(*provider.ListUsersOutput, bool) bool,
) error {

	args := m.Called(input, pager)
	if err := args.Error(1); err != nil {
		return err
	}

	pager(args.Get(0).(*provider.ListUsersOutput), true)
	return nil
}
