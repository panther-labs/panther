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
	"github.com/kelseyhightower/envconfig"
	"github.com/panther-labs/panther/internal/compliance/compliance_api/handlers"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var methodHandlers = map[string]gatewayapi.RequestHandler{
	"GET /describe-org":      handlers.DescribeOrg,
	"GET /describe-policy":   handlers.DescribePolicy,
	"GET /describe-resource": handlers.DescribeResource,
	"GET /org-overview":      handlers.GetOrgOverview,
	"GET /status":            handlers.GetStatus,

	"POST /delete": handlers.DeleteStatus,
	"POST /status": handlers.SetStatus,
	"POST /update": handlers.UpdateMetadata,
}

func main() {
	envconfig.MustProcess("", &handlers.Env)
	lambda.Start(gatewayapi.LambdaProxy(methodHandlers))
}
