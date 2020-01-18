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
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/core/users_api/gateway"
)

func TestHandleForgotPasswordGeneratePlainTextEmail(t *testing.T) {
	mockGateway := &gateway.MockUserGateway{}
	userGateway = mockGateway
	appDomainURL = "dev.runpanther.pizza"
	username := "user-123"
	poolID := "pool-123"
	codeParam := "123456"
	event := events.CognitoEventUserPoolsCustomMessage{
		CognitoEventUserPoolsHeader: events.CognitoEventUserPoolsHeader{
			UserName:   username,
			UserPoolID: poolID,
		},
		Request: events.CognitoEventUserPoolsCustomMessageRequest{
			CodeParameter: codeParam,
		},
	}
	mockGateway.On("GetUser", &username, &poolID).Return(&models.User{
		GivenName:  aws.String("user-given-name-123"),
		FamilyName: aws.String("user-family-name-123"),
		Email:      aws.String("user@test.pizza"),
	}, nil)

	e, err := handleForgotPassword(&event)
	assert.Nil(t, err)
	assert.NotNil(t, e)
}
