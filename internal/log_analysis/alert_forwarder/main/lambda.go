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
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/alert_forwarder/forwarder"
	alertApiModels "github.com/panther-labs/panther/internal/log_analysis/alerts_api/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/metrics"
)

var handler *forwarder.Handler

func init() {
	// Required only once per Lambda container
	Setup()
	// TODO: revisit this. Not sure why we need Dimension sets and why just an array of dimensions is not enough
	metricsLogger := metrics.MustLogger([]metrics.DimensionSet{
		{
			"AnalysisType",
			"Severity",
		},
		{
			"AnalysisType",
			"AnalysisID",
		},
		{
			"AnalysisType",
		},
	})
	cache := forwarder.NewCache(policyClient)
	handler = &forwarder.Handler{
		SqsClient:        sqsClient,
		DdbClient:        ddbClient,
		Cache:            cache,
		AlertingQueueURL: env.AlertingQueueURL,
		AlertTable:       env.AlertsTable,
		MetricsLogger:    metricsLogger,
	}
}

func main() {
	lambda.Start(handle)
}

func handle(ctx context.Context, event events.DynamoDBEvent) error {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	return reporterHandler(lc, event)
}

func reporterHandler(lc *lambdacontext.LambdaContext, event events.DynamoDBEvent) (err error) {
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("messageCount", len(event.Records)))
	}()

	// Note that if there is an error in processing any of the messages in the batch, the whole batch will be retried.
	for _, record := range event.Records {
		oldAlertDedupEvent, unmarshalErr := alertApiModels.FromDynamodDBAttribute(record.Change.OldImage)
		if unmarshalErr != nil {
			operation.LogError(errors.Wrapf(err, "failed to unmarshal item"))
			// continuing since there is nothing we can do here
			continue
		}

		newAlertDedupEvent, unmarshalErr := alertApiModels.FromDynamodDBAttribute(record.Change.NewImage)
		if unmarshalErr != nil {
			operation.LogError(errors.Wrapf(err, "failed to unmarshal item"))
			// continuing since there is nothing we can do here
			continue
		}

		if newAlertDedupEvent == nil {
			// This can happen only if someone manually deleted entries from DDB
			// It shouldn't happen under normal operation - only if someone altered the DDB manually.
			// We can skip these records since there is nothing we can do in this scenario
			operation.LogWarn(errors.New("skipping deleted record"))
			continue
		}

		if err = handler.Do(oldAlertDedupEvent, newAlertDedupEvent); err != nil {
			return errors.Wrap(err, "encountered issue while handling deduplication event")
		}
	}
	return nil
}
