// Package api defines CRUD actions for the Cognito Api.
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
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/panther-labs/panther/internal/core/users_api/cognito"
)

// The API has receiver methods for each of the handlers.
type API struct{}

// RequesterID when the backend is requesting users-api operations, e.g. first deployment.
const systemUserID = "00000000-0000-4000-8000-000000000000"

var (
	awsSession               = session.Must(session.NewSession(aws.NewConfig().WithMaxRetries(10)))
	appDomainURL             = os.Getenv("APP_DOMAIN_URL")
	userGateway  cognito.API = cognito.New(awsSession, os.Getenv("USER_POOL_ID"))
)
