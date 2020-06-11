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

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"go.uber.org/zap"
)

type CognitoUserPoolMfaProperties struct {
	UserPoolID string `json:"UserPoolId" validate:"required"`
}

// Enforce SoftwareToken MFA (without SMS as a fallback)
func customCognitoUserPoolMfa(_ context.Context, event cfn.Event) (physicalID string, outputs map[string]interface{}, err error) {
	switch event.RequestType {
	case cfn.RequestDelete:
		// We could disable MFA when this resource is deleted, but we have no need for that right now.
		return

	default:
		var props CognitoUserPoolMfaProperties
		if err = parseProperties(event.ResourceProperties, &props); err != nil {
			return
		}

		physicalID = fmt.Sprintf("custom:cognito-user-pool:%s:mfa", props.UserPoolID)

		// Create and Update will set the MFA config for the user pool
		zap.L().Info("enabling TOTP for user pool", zap.String("userPoolId", props.UserPoolID))
		_, err = cognitoClient.SetUserPoolMfaConfig(&cognitoidentityprovider.SetUserPoolMfaConfigInput{
			MfaConfiguration: aws.String("ON"),
			SoftwareTokenMfaConfiguration: &cognitoidentityprovider.SoftwareTokenMfaConfigType{
				Enabled: aws.Bool(true),
			},
			UserPoolId: &props.UserPoolID,
		})
		return
	}
}
