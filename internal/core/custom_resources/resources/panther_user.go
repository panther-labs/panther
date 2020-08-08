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

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type PantherUserProperties struct {
	GivenName  string
	FamilyName string
	Email      string `validate:"required,email"`
}

const usersAPI = "panther-users-api"

func customPantherUser(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate:
		var props PantherUserProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return event.PhysicalResourceID, nil, err
		}

		userID, err := inviteUser(props)
		if err != nil {
			// We want to log an error, but not fail the CloudFormation and trigger a rollback.
			// The user can manually invoke users-api to invite a user if this fails.
			zap.L().Error("failed to invite user - you'll need to invoke "+usersAPI+" directly "+
				"(see https://docs.runpanther.io/user-guide/help/troubleshooting)",
				zap.Any("user", props), zap.Error(err))
			userID = "error"
		}

		return "custom:panther-user:" + userID, nil, nil

	default:
		// This custom resource is only used to bootstrap the first user.
		// We used to support updates and deletes, but then CloudFormation could conflict with
		// changes made in the Panther web app.
		// So now we ignore updates and deletes, just like the AnalysisSet.
		return event.PhysicalResourceID, nil, nil
	}
}

// Returns the Panther userID
func inviteUser(props PantherUserProperties) (string, error) {
	input := models.LambdaInput{
		InviteUser: &models.InviteUserInput{
			RequesterID: aws.String(systemUserID),
			GivenName:   &props.GivenName,
			FamilyName:  &props.FamilyName,
			Email:       &props.Email,
		},
	}
	var output models.InviteUserOutput

	if err := genericapi.Invoke(lambdaClient, usersAPI, &input, &output); err != nil {
		return "", err
	}

	return *output.ID, nil
}
