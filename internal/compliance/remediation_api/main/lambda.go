package main

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
	"github.com/aws/aws-lambda-go/lambda"

	apihandlers "github.com/panther-labs/panther/internal/compliance/remediation_api/handlers"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var methodHandlers = map[string]gatewayapi.RequestHandler{
	"GET /":                apihandlers.GetRemediations,
	"POST /remediate":      apihandlers.RemediateResource,
	"POST /remediateasync": apihandlers.RemediateResourceAsync,
}

func main() {
	lambda.Start(gatewayapi.LambdaProxy(methodHandlers))
}
