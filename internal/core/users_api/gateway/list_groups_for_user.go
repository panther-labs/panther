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

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ListGroupsForUser calls cognito api to list groups that a user belongs to
func (g *UsersGateway) ListGroupsForUser(id *string, userPoolID *string) ([]*models.Group, error) {
	o, err := g.userPoolClient.AdminListGroupsForUser(&provider.AdminListGroupsForUserInput{
		Username:   id,
		UserPoolId: userPoolID,
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "cognito.AdminListGroupsForUser", Err: err}
	}

	groups := make([]*models.Group, len(o.Groups))
	for i, og := range o.Groups {
		groups[i] = &models.Group{Description: og.Description, Name: og.GroupName}
	}
	return groups, nil
}
