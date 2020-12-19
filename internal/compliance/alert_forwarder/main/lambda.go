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

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/compliance/alert_forwarder/forwarder"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/metrics"
	"github.com/panther-labs/panther/pkg/oplog"
)

const alertConfigKey = "alertConfig"

var (
	validate = validator.New()
	handler  *forwarder.Handler
)

func main() {
	// Required only once per Lambda container
	Setup()
	// TODO: revisit this. Not sure why we neeed Dimension sets and why just an array of dimensions is not enough
	metricsLogger := metrics.MustLogger([]metrics.DimensionSet{
		{
			"AnalysisType",
			"Severity",
		},
		{
			"AnalysisType",
		},
	})
	handler = &forwarder.Handler{
		SqsClient:        sqsClient,
		DdbClient:        ddbClient,
		AlertingQueueURL: env.AlertingQueueURL,
		AlertTable:       env.AlertsTable,
		MetricsLogger:    metricsLogger,
	}
	lambda.Start(handle)
}

func handle(ctx context.Context, event events.DynamoDBEvent) error {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	return reporterHandler(lc, event)
}

func reporterHandler(lc *lambdacontext.LambdaContext, event events.DynamoDBEvent) (err error) {
	operation := oplog.NewManager("cloudsec", "alert_forwarder").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("messageCount", len(event.Records)))
	}()

	for _, record := range event.Records {
		// Skip events that aren't new
		if record.Change.NewImage == nil {
			zap.L().Debug("Skipping record", zap.Any("record", record))
			continue
		}
		alert := models.Alert{}
		if err = jsoniter.Unmarshal(record.Change.NewImage[alertConfigKey].Binary(), &alert); err != nil {
			operation.LogError(errors.Wrap(err, "Failed to unmarshal item"))
			continue
		}

		if err = validate.Struct(alert); err != nil {
			operation.LogError(errors.Wrap(err, "invalid message received"))
			continue
		}

		if err = handler.Do(alert); err != nil {
			err = errors.Wrap(err, "encountered issue while handling policy event")
			return err
		}
	}
	return nil
}
