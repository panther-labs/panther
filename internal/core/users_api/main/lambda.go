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
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/internal/core/users_api/api"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var router = genericapi.NewRouter("api", "users", models.Validator(), &api.API{})

func lambdaHandler(ctx context.Context, input json.RawMessage) (interface{}, error) {
	lambdalogger.ConfigureGlobal(ctx, nil)

	// There are two different kinds of requests handled by this function:
	// Cognito triggers and standard users-api direct invocations
	var header events.CognitoEventUserPoolsHeader
	if err := jsoniter.Unmarshal(input, &header); err == nil && header.TriggerSource != "" {
		return api.CognitoTrigger(header, input)
	}

	var apiRequest models.LambdaInput
	if err := jsoniter.Unmarshal(input, &apiRequest); err != nil {
		return nil, &genericapi.InvalidInputError{
			Message: "json unmarshal of request failed: " + err.Error()}
	}

	return router.Handle(&apiRequest)
}

func main() {
	lambda.Start(lambdaHandler)
}
