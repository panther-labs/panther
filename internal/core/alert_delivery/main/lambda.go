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

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/api"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

var router = genericapi.NewRouter("api", "delivery", nil, api.API{})

// lambdaHandler handles two different kinds of requests:
// 1. SQSMessage trigger that takes data from the queue or can be directly invoked
// 2. HTTP API for re-sending an alert to the specified outputs
// 3. HTTP API for sending a test alert
func lambdaHandler(ctx context.Context, input json.RawMessage) (output interface{}, err error) {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := oplog.NewManager("core", "alert_delivery").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err)
	}()

	apiRequest := models.LambdaInput{}
	if err := jsoniter.Unmarshal(input, &apiRequest); err == nil {
		return router.HandleWithContext(ctx, &apiRequest)
	}

	// If neither handler captured the request, return nothing
	return nil, err
}

func main() {
	api.Setup()
	lambda.Start(lambdaHandler)
}
