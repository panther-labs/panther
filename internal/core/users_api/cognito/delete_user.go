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
	"github.com/aws/aws-sdk-go/aws/awserr"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/genericapi"
)

func (g *UsersGateway) DeleteUser(id *string) error {
	// Invalidate refresh token (access tokens are still valid for 1h)
	if _, err := g.userPoolClient.AdminUserGlobalSignOut(&provider.AdminUserGlobalSignOutInput{
		Username:   id,
		UserPoolId: g.userPoolID,
	}); err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == provider.ErrCodeUserNotFoundException {
			zap.L().Warn("user is already deleted", zap.String("userId", *id))
			return nil
		}
		return &genericapi.AWSError{Method: "cognito.AdminUserGlobalSignOut", Err: err}
	}

	if _, err := g.userPoolClient.AdminDeleteUser(&provider.AdminDeleteUserInput{
		Username:   id,
		UserPoolId: g.userPoolID,
	}); err != nil {
		return &genericapi.AWSError{Method: "cognito.AdminDeleteUser", Err: err}
	}

	return nil
}
