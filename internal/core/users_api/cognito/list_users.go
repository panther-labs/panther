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
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ListUsers calls cognito api to list users that belongs to a user pool
func (g *UsersGateway) ListUsers(input *models.ListUsersInput) ([]models.User, error) {
	cognitoInput := &provider.ListUsersInput{UserPoolId: g.userPoolID}
	var result []models.User

	// There will almost always be 1 page of users and there is no paging for this in the frontend.
	// In the very unlikely event there is more than 1 page, we loop over all pages here.
	err := g.userPoolClient.ListUsersPages(cognitoInput, func(page *provider.ListUsersOutput, lastPage bool) bool {
		for _, u := range page.Users {
			user := toUser(u.UserCreateDate, u.Username, u.UserStatus, u.Attributes)

			if input.Status != nil && *input.Status != aws.StringValue(user.Status) {
				continue // filter by status
			}
			if search := aws.StringValue(input.Contains); search != "" {
				if !strings.Contains(strings.ToLower(aws.StringValue(user.GivenName)), search) &&
					!strings.Contains(strings.ToLower(aws.StringValue(user.FamilyName)), search) &&
					!strings.Contains(strings.ToLower(aws.StringValue(user.Email)), search) {

					continue // filter by name/email
				}
			}

			result = append(result, *user)
		}
		return true
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "cognito.ListUsers", Err: err}
	}

	// Sort (default: email ascending)
	sortDescending := aws.StringValue(input.SortDir) == "descending"
	switch aws.StringValue(input.SortBy) {
	case "firstName":
		sort.Slice(result, func(i, j int) bool {
			if sortDescending {
				return *result[i].GivenName > *result[j].GivenName
			}
			return *result[i].GivenName < *result[j].GivenName
		})
	case "lastName":
		sort.Slice(result, func(i, j int) bool {
			if sortDescending {
				return *result[i].FamilyName > *result[j].FamilyName
			}
			return *result[i].FamilyName < *result[j].FamilyName
		})
	case "createdAt":
		sort.Slice(result, func(i, j int) bool {
			if sortDescending {
				return *result[i].CreatedAt > *result[j].CreatedAt
			}
			return *result[i].CreatedAt < *result[j].CreatedAt
		})
	default: // email
		sort.Slice(result, func(i, j int) bool {
			if sortDescending {
				return *result[i].Email > *result[j].Email
			}
			return *result[i].Email < *result[j].Email
		})
	}

	return result, nil
}
