package main

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
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/panther-labs/panther/internal/core/analysis_api/handlers"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var methodHandlers = map[string]gatewayapi.RequestHandler{
	// Policies only
	"GET /list":      handlers.ListPolicies,
	"GET /policy":    handlers.GetPolicy,
	"POST /policy":   handlers.CreatePolicy,
	"POST /suppress": handlers.Suppress,
	"POST /update":   handlers.ModifyPolicy,
	"POST /upload":   handlers.BulkUpload,

	// Rules only
	"GET /rule":         handlers.GetRule,
	"POST /rule":        handlers.CreateRule,
	"GET /rule/list":    handlers.ListRules,
	"POST /rule/update": handlers.ModifyRule,

	// Rules and Policies
	"POST /delete": handlers.DeletePolicies,
	"GET /enabled": handlers.GetEnabledPolicies,
	"POST /test":   handlers.TestPolicy,
}

func main() {
	handlers.Setup()
	lambda.Start(gatewayapi.LambdaProxy(methodHandlers))
}
