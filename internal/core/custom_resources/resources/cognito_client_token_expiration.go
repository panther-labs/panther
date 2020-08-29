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
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"go.uber.org/zap"
)

type CognitoClientTokenExpirationProperties struct {
	AccessTokenValidityMinutes  *int64 `json:",string"`
	IDTokenValidityMinutes      *int64 `json:"IdTokenValidityMinutes,string"`
	RefreshTokenValidityMinutes *int64 `json:",string"`

	AppClientID string `json:"AppClientId" validate:"required"`
	UserPoolID  string `json:"UserPoolId" validate:"required"`
}

// Configurable user pool client token validity (not yet supported in CloudFormation)
func customCognitoClientTokenExpiration(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, nil

	default:
		// Create and Update will set the token expiration on the user pool client
		var props CognitoClientTokenExpirationProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return event.PhysicalResourceID, nil, err
		}

		physicalID := "custom:cognito-client-token-expiration:" + props.AppClientID

		// The SDK does not support partial updates, so we have to first fetch the existing config
		settings, err := cognitoClient.DescribeUserPoolClient(&cognitoidentityprovider.DescribeUserPoolClientInput{
			ClientId:   &props.AppClientID,
			UserPoolId: &props.UserPoolID,
		})
		if err != nil {
			return physicalID, nil, err
		}
		client := settings.UserPoolClient

		zap.L().Info("updating user pool client token expiration", zap.Any("properties", props))
		_, err = cognitoClient.UpdateUserPoolClient(&cognitoidentityprovider.UpdateUserPoolClientInput{
			AccessTokenValidity:  props.AccessTokenValidityMinutes,
			IdTokenValidity:      props.IDTokenValidityMinutes,
			RefreshTokenValidity: props.RefreshTokenValidityMinutes,
			TokenValidityUnits: &cognitoidentityprovider.TokenValidityUnitsType{
				AccessToken:  aws.String("minutes"),
				IdToken:      aws.String("minutes"),
				RefreshToken: aws.String("minutes"),
			},

			AllowedOAuthFlows:               client.AllowedOAuthFlows,
			AllowedOAuthFlowsUserPoolClient: client.AllowedOAuthFlowsUserPoolClient,
			AllowedOAuthScopes:              client.AllowedOAuthScopes,
			AnalyticsConfiguration:          client.AnalyticsConfiguration,
			CallbackURLs:                    client.CallbackURLs,
			ClientId:                        client.ClientId,
			ClientName:                      client.ClientName,
			DefaultRedirectURI:              client.DefaultRedirectURI,
			ExplicitAuthFlows:               client.ExplicitAuthFlows,
			LogoutURLs:                      client.LogoutURLs,
			PreventUserExistenceErrors:      client.PreventUserExistenceErrors,
			ReadAttributes:                  client.ReadAttributes,
			SupportedIdentityProviders:      client.SupportedIdentityProviders,
			UserPoolId:                      client.UserPoolId,
			WriteAttributes:                 client.WriteAttributes,
		})
		return physicalID, nil, err
	}
}
