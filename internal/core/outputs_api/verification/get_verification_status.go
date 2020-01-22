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
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ses"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var emailFromAddress = os.Getenv("MAIL_FROM")

// GetVerificationStatus returns the verification status of an email address
func (verification *OutputVerification) GetVerificationStatus(input *models.AlertOutput) (*string, error) {
	if *input.OutputType != "email" {
		result := models.VerificationStatusSuccess
		return &result, nil
	}

	if emailFromAddress == "" {
		return nil, &genericapi.InvalidInputError{Message:"Cannot add email destination. You need to configure an email that will be used as source email"}
	}

	// Check SES to see if it has been verified already
	request := &ses.GetIdentityVerificationAttributesInput{
		Identities: []*string{input.OutputConfig.Email.DestinationAddress},
	}
	response, err := verification.sesClient.GetIdentityVerificationAttributes(request)
	if err != nil {
		return nil, err
	}
	verificationStatusAttributes := response.VerificationAttributes[aws.StringValue(input.OutputConfig.Email.DestinationAddress)]
	if verificationStatusAttributes == nil {
		return aws.String(models.VerificationStatusNotStarted), nil
	}

	switch *verificationStatusAttributes.VerificationStatus {
	case ses.VerificationStatusSuccess:
		return aws.String(models.VerificationStatusSuccess), nil
	case ses.VerificationStatusNotStarted:
		return aws.String(models.VerificationStatusNotStarted), nil
	case ses.VerificationStatusPending:
		return aws.String(models.VerificationStatusPending), nil
	default:
		return aws.String(models.VerificationStatusFailed), nil
	}
}
