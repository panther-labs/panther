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
	"net/url"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/matcornic/hermes"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/custom_message/email"
)

func handleForgotPassword(event *events.CognitoEventUserPoolsCustomMessage) (*events.CognitoEventUserPoolsCustomMessage, error) {
	zap.L().Info("generate forget password email for:" + event.UserName)

	user, err := userGateway.GetUser(&event.UserName)
	if err != nil {
		zap.L().Error("failed to generate forget password html email for:"+event.UserName, zap.Error(err))
		return nil, err
	}

	emailParams := hermes.Email{
		Body: hermes.Body{
			Name: *user.GivenName + " " + *user.FamilyName,
			Intros: []string{
				`A password reset has been requested for this email address.
If you did not request a password reset, you can ignore this email.`,
			},
			Actions: []hermes.Action{
				{
					Instructions: "To set a new password for your Panther account, please click here:",
					Button: hermes.Button{
						TextColor: "#FFFFFF",
						Color:     "#6967F4", // Optional action button color
						Text:      "Reset my password",
						Link:      "https://" + appDomainURL + "/password-reset?token=" + event.Request.CodeParameter + "&email=" + url.QueryEscape(*user.Email),
					},
				},
			},
			Outros: []string{
				"Need help, or have questions? Just email us at support@runpanther.io, we'd love to help.",
			},
		},
	}
	// Generate an HTML email with the provided contents (for modern clients)
	emailBody, err := email.PantherEmailTemplate.GeneratePlainText(emailParams)

	// We have to do this because most email clients are not friendly with basic new line markup
	// replacing \n with a <br /> is the easiest way to mitigate this issue
	emailBody = strings.Replace(emailBody, "\n", "<br />", -1)
	if err != nil {
		zap.L().Error("failed to generate forget password html email for:"+event.UserName, zap.Error(err))
		return nil, err
	}
	event.Response.EmailMessage = emailBody
	event.Response.EmailSubject = "Panther Password Reset"
	return event, nil
}
