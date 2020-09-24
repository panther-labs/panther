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
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/process"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// The panther-datacatalog-updater lambda is responsible for managing Glue partitions as data is created.

type DataCatalogEvent struct {
	events.SQSEvent
	process.SyncEvent
	SyncDatabase *process.SyncDatabaseEvent
	SyncTable    *process.SyncTableEvent
}

func handle(ctx context.Context, event DataCatalogEvent) (err error) {
	lc, log := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err,
			zap.Int("sqsMessageCount", len(event.Records)))
	}()

	if event.SyncDatabase != nil {
		var result map[string]*process.SyncDatabaseOutput
		result, err = process.SyncDatabase(ctx, event.SyncDatabase)
		log.Info("database sync submitted", zap.Any("tasks", result))
		return
	}

	if event.SyncTable != nil {
		err = process.SyncTable(ctx, event.SyncTable)
		return
	}

	if event.Sync {
		lambdaDeadline, _ := ctx.Deadline()
		syncDuration := time.Since(lambdaDeadline) / 2 //  allocate a fraction of total time, this value will be negative!
		syncDeadline := lambdaDeadline.Add(syncDuration)
		err = process.Sync(&event.SyncEvent, syncDeadline)
		return
	}
	err = process.SQS(event.SQSEvent)
	return
}

func main() {
	process.Setup()
	lambda.Start(handle)
}
