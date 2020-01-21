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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)


// OutputVerificationAPI defines the interface for the outputs table which can be used for mocking.
type OutputVerificationAPI interface {
	// GetVerificationStatus gets the verification status of an email
	GetVerificationStatus(output *models.AlertOutput) (*string, error)

	// VerifyOutput verifies an email address
	VerifyOutput(output *models.AlertOutput) (*models.AlertOutput, error)
}

// OutputVerification encapsulates a connection to the Dynamo rules table.
type OutputVerification struct {
	sesClient    sesiface.SESAPI
	lambdaClient lambdaiface.LambdaAPI
}

// NewVerification creates a new OutputVerification struct
func NewVerification(sess *session.Session) *OutputVerification {
	return &OutputVerification{
		sesClient:    ses.New(sess),
		lambdaClient: lambda.New(sess),
	}
}
