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

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/process"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// The panther-datacatalog-updater lambda is responsible for managing Glue partitions as data is created.

func handle(ctx context.Context, event *process.DataCatalogEvent) (err error) {
	lc, logger := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err,
			zap.Int("sqsMessageCount", len(event.Records)))
	}()

	// This lambda handles 3 type of events:
	switch {
	// 1. A SyncDatabase event to trigger a full database sync (used by custom resource manager)
	case event.SyncDatabaseEvent != nil:
		ctx = lambdalogger.Context(ctx, logger)
		err = process.HandleSyncEvent(ctx, event.SyncDatabaseEvent)
	// 2. A SyncTablePartitions event to trigger a single table sync (triggered recursively by sync database events)
	case event.SyncTablePartitions != nil:
		ctx = lambdalogger.Context(ctx, logger)
		err = process.HandleSyncTableEvent(ctx, event.SyncTablePartitions)
	// 3. An SQS message notifying about new data written and possibly needing a new partition to be added
	default:
		err = process.SQS(event.SQSEvent)
	}
	return
}

func main() {
	process.Setup()
	lambda.Start(handle)
}
