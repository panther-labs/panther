package api

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
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ListUsers lists details for each user in Panther.
func (API) ListUsers(input *models.ListUsersInput) (*models.ListUsersOutput, error) {
	if input.Contains != nil {
		decoded, err := url.QueryUnescape(*input.Contains)
		if err != nil {
			return nil, &genericapi.InvalidInputError{
				Message: fmt.Sprintf("\"%s\" url decoding failed: %v", *input.Contains, err)}
		}
		input.Contains = aws.String(strings.ToLower(strings.TrimSpace(decoded)))
	}

	users, err := userGateway.ListUsers(input)
	if err != nil {
		return nil, err
	}

	return &models.ListUsersOutput{Users: users}, nil
}
