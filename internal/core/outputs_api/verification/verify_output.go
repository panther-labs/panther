package verification

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ses"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

// VerifyOutput performs verification on a AlertOutput
// Note that in case the output is not an email, no action is performed.
// In case it is an email, we use SES's email verification mechanism.
func (verification *OutputVerification) VerifyOutput(input *models.AlertOutput) (*models.AlertOutput, error) {
	if *input.OutputType != "email" {
		return input, nil
	}
	request := &ses.SendCustomVerificationEmailInput{
		EmailAddress:         input.OutputConfig.Email.DestinationAddress,
		ConfigurationSetName: aws.String(sesConfigurationSet),
		TemplateName:         aws.String(emailVerificationTemplate),
	}
	response, err := verification.sesClient.SendCustomVerificationEmail(request)

	if err != nil {
		return nil, err
	}

	zap.L().Info("sent a verification email", zap.String("messageId", response.String()))
	input.VerificationStatus = aws.String(models.VerificationStatusPending)
	return input, nil
}
