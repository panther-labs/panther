// Package api defines CRUD actions for the Cognito Api.
package api

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

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"

	"github.com/panther-labs/panther/internal/core/users_api/gateway"
	users "github.com/panther-labs/panther/internal/core/users_api/table"
)

// The API has receiver methods for each of the handlers.
type API struct{}

var (
	organizationAPI = os.Getenv("ORGANIZATION_API")
	awsSession      = session.Must(session.NewSession())

	lambdaClient lambdaiface.LambdaAPI = lambda.New(awsSession)
	userGateway  gateway.API           = gateway.New(awsSession)
	userTable    users.API             = users.New(os.Getenv("USERS_TABLE_NAME"), awsSession)
)
