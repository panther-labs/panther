package api

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
	"errors"
	"fmt"
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"
)

// This is similar to the template in deployments/core/cognito.yml for the invite email.
// nolint: gosec
const passwordResetTemplate = `
<br />Hi %s,
<br />
<br />A password reset has been triggered for this email address.
<br />
<br />To set a new password for your Panther account, please click here:
<br />https://%s/password-reset?token=%s&email=%s
<br />
<br />Need help, or have questions? Just email us at support@runpanther.io, we'd love to help.
<br />
<br />Yours truly,
<br />Panther - https://runpanther.io
<br />
<br /><small>Copyright © 2020 Panther Labs Inc. All rights reserved.</small>
`

// Instead of the standard API call, the users-api was invoked by Cognito as a custom message trigger
func CognitoTrigger(event *events.CognitoEventUserPoolsCustomMessage) (*events.CognitoEventUserPoolsCustomMessage, error) {
	zap.L().Info("handling cognito trigger", zap.String("source", event.TriggerSource))

	switch ts := event.TriggerSource; ts {
	case "CustomMessage_ForgotPassword":
		return handleForgotPassword(event)
	default:
		return event, nil
	}
}

func handleForgotPassword(event *events.CognitoEventUserPoolsCustomMessage) (*events.CognitoEventUserPoolsCustomMessage, error) {
	zap.L().Info("generating forget password email for:" + event.UserName)

	// Name defaults to blank if for some reason it isn't defined
	givenName, _ := event.Request.UserAttributes["given_name"].(string)

	// Email, however, is required to generate the URL
	email, ok := event.Request.UserAttributes["email"].(string)
	if !ok {
		zap.L().Error("email does not exist in user attributes", zap.Any("event", event))
		return nil, errors.New("email attribute not found")
	}

	event.Response.EmailMessage = fmt.Sprintf(passwordResetTemplate,
		givenName,
		appDomainURL,
		event.Request.CodeParameter,
		url.QueryEscape(email),
	)
	event.Response.EmailSubject = "Panther Password Reset"
	return event, nil
}
