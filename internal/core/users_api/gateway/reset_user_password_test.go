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

	"github.com/aws/aws-sdk-go/aws"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	providerI "github.com/aws/aws-sdk-go/service/cognitoidentityprovider/cognitoidentityprovideriface"
	"github.com/stretchr/testify/assert"
)

type mockResetUserPasswordClient struct {
	providerI.CognitoIdentityProviderAPI
	serviceErr bool
}

func (m *mockResetUserPasswordClient) AdminResetUserPassword(
	*provider.AdminResetUserPasswordInput) (*provider.AdminResetUserPasswordOutput, error) {

	if m.serviceErr {
		return nil, errors.New("cognito does not exist")
	}
	return &provider.AdminResetUserPasswordOutput{}, nil
}

func TestResetUserPassword(t *testing.T) {
	gw := &UsersGateway{userPoolClient: &mockResetUserPasswordClient{}}
	assert.NoError(t, gw.ResetUserPassword(aws.String("user123"), aws.String("userPoolId")))
}

func TestResetUserPasswordFailed(t *testing.T) {
	gw := &UsersGateway{userPoolClient: &mockResetUserPasswordClient{serviceErr: true}}
	assert.Error(t, gw.ResetUserPassword(aws.String("user123"), aws.String("userPoolId")))
}
