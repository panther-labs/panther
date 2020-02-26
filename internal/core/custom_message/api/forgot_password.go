package custommessage

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
	"fmt"
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"
)

// This is similar to the template in deployments/core/cognito.yml for the invite email.
const template = `
<br />Hi %s %s,
<br />
<br />A password reset has been requested for this email address. If you did not request a password reset, you can ignore this email.
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

func handleForgotPassword(event *events.CognitoEventUserPoolsCustomMessage) (*events.CognitoEventUserPoolsCustomMessage, error) {
	zap.L().Info("generating forget password email for:" + event.UserName)

	user, err := userGateway.GetUser(&event.UserName)
	if err != nil {
		zap.L().Error("failed to get user "+event.UserName, zap.Error(err))
		return nil, err
	}

	event.Response.EmailMessage = fmt.Sprintf(template,
		aws.StringValue(user.GivenName), aws.StringValue(user.FamilyName),
		appDomainURL, event.Request.CodeParameter, url.QueryEscape(aws.StringValue(user.Email)))
	event.Response.EmailSubject = "Panther Password Reset"
	return event, nil
}
