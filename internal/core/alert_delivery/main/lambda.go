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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/core/alert_delivery/delivery"
	"github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

var validate = validator.New()

func lambdaHandler(ctx context.Context, event events.SQSEvent) (err error) {
	var alerts []*models.Alert

	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := oplog.NewManager("core", "alert_delivery").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("numEvents", len(event.Records)), zap.Int("numAlerts", len(alerts)))
	}()

	for _, record := range event.Records {
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
	return err
}

func main() {
	lambda.Start(lambdaHandler)
}
