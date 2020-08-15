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
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/api"
	delivery "github.com/panther-labs/panther/internal/core/alert_delivery/delivery"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

var validate = validator.New()

var router = genericapi.NewRouter("api", "delivery", nil, api.API{})

// lambdaHandler handles two different kinds of requests:
// 1. SQS event triggers that processes a batch of alerts periodically
// 2. HTTP requests for direct invocation
func lambdaHandler(ctx context.Context, input json.RawMessage) (output interface{}, err error) {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := oplog.NewManager("core", "alert_delivery").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err)
	}()

	// SQS trigger
	var events events.SQSEvent
	if err := jsoniter.Unmarshal(input, &events); err == nil {
		var alerts []*models.Alert

		for _, record := range events.Records {
			alert := &models.Alert{}
			if err = jsoniter.UnmarshalFromString(record.Body, alert); err != nil {
				operation.LogError(errors.Wrap(err, "Failed to unmarshal item"))
				continue
			}
			if err = validate.Struct(alert); err != nil {
				operation.LogError(errors.Wrap(err, "invalid message received"))
				continue
			}
			alerts = append(alerts, alert)
		}
		delivery.HandleAlerts(alerts)
		return nil, err
	}

	// HTTP request
	api.Setup()
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
