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
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"
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

func CognitoTrigger(header events.CognitoEventUserPoolsHeader, input json.RawMessage) (interface{}, error) {
	zap.L().Info("handling cognito trigger", zap.Any("header", header))

	if header.TriggerSource == "CustomMessage_ForgotPassword" {
		return handleForgotPassword(input)
	}

	// Ignore other types of triggers
	return input, nil
}

func handleForgotPassword(input json.RawMessage) (*events.CognitoEventUserPoolsCustomMessage, error) {
	var event events.CognitoEventUserPoolsCustomMessage
	if err := jsoniter.Unmarshal(input, &event); err != nil {
		return nil, err
	}

	// Name defaults to blank if for some reason it isn't defined
	givenName, _ := event.Request.UserAttributes["given_name"].(string)

	// Email, however, is required to generate the URL
	email, ok := event.Request.UserAttributes["email"].(string)
	if !ok {
		zap.L().Error("email does not exist in user attributes", zap.Any("event", event))
		return nil, errors.New("email attribute not found")
	}

	// IMPORTANT! html.EscapeString for any user-defined fields to prevent an injection attack
	event.Response.EmailMessage = fmt.Sprintf(passwordResetTemplate,
		html.EscapeString(givenName),
		appDomainURL,
		event.Request.CodeParameter,
		url.QueryEscape(email),
	)
	event.Response.EmailSubject = "Panther Password Reset"
	return &event, nil
}
