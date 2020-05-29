package resources

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
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type PantherUserProperties struct {
	GivenName  string
	FamilyName string
	Email      string `validate:"required,email"`
}

func customPantherUser(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate:
		var props PantherUserProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		userID, err := inviteUser(props)
		if err != nil {
			return "", nil, err
		}
		return "custom:panther-user:" + userID, map[string]interface{}{"UserId": userID}, nil

	case cfn.RequestUpdate:
		var props PantherUserProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		split := strings.Split(event.PhysicalResourceID, ":")
		userID := split[len(split)-1]
		return event.PhysicalResourceID, map[string]interface{}{"UserId": userID}, updateUser(userID, props)

	case cfn.RequestDelete:
		split := strings.Split(event.PhysicalResourceID, ":")
		if len(split) < 3 {
			// invalid ID (e.g. create failed)
			return event.PhysicalResourceID, nil, nil
		}

		userID := split[len(split)-1]
		return event.PhysicalResourceID, nil, deleteUser(userID)

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

// Returns the Panther userID
func inviteUser(props PantherUserProperties) (string, error) {
	input := models.LambdaInput{
		InviteUser: &models.InviteUserInput{
			GivenName:  &props.GivenName,
			FamilyName: &props.FamilyName,
			Email:      &props.Email,
		},
	}
	var output models.InviteUserOutput

	if err := genericapi.Invoke(getLambdaClient(), "panther-users-api", &input, &output); err != nil {
		return "", err
	}

	return *output.ID, nil
}

func updateUser(userID string, props PantherUserProperties) error {
	input := models.LambdaInput{
		UpdateUser: &models.UpdateUserInput{
			ID:         &userID,
			GivenName:  &props.GivenName,
			FamilyName: &props.FamilyName,
			Email:      &props.Email,
		},
	}
	return genericapi.Invoke(getLambdaClient(), "panther-users-api", &input, nil)
}

func deleteUser(userID string) error {
	input := models.LambdaInput{
		RemoveUser: &models.RemoveUserInput{ID: &userID},
	}
	return genericapi.Invoke(getLambdaClient(), "panther-users-api", &input, nil)
}
