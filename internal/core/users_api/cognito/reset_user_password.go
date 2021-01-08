package cognito

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

	"github.com/panther-labs/panther/pkg/genericapi"
)

// ResetUserPassword calls cognito api to reset user password
func (g *UsersGateway) ResetUserPassword(id *string) error {
	if _, err := g.userPoolClient.AdminResetUserPassword(&provider.AdminResetUserPasswordInput{
		Username:   id,
		UserPoolId: g.userPoolID,
	}); err != nil {
		return &genericapi.AWSError{Method: "cognito.AdminResetUserPassword", Err: err}
	}

	return nil
}
