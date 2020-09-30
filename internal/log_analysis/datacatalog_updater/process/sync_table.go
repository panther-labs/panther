package process

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
	"runtime"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// SyncTableEvent initializes or continues a gluetasks.SyncTablePartitions task
type SyncTableEvent struct {
	// Use a common trace id (the SyncDatabase request id) for all events triggered by a sync event.
	// This is used in all logging done by the SyncTablePartitions task to be able to trace all lambda invocations
	// back to their original SyncDatabase request.
	TraceID string
	// NumCalls keeps track of the number of recursive calls for the specific sync table event.
	// It acts as a guard against infinite recursion.
	NumCalls int
	// Embed the full sync table partitions task state
	// This allows us to continue the task by recursively calling the lambda.
	// The task carries all status information over
	gluetasks.SyncTablePartitions
}

// Max number of calls for a single table sync.
// Each year of hourly partitions is 8760 partitions.
// Avg page size seems to vary between 100-200 partitions per page.
// We expect ~100 pages per year of data.
// Each invocation should handle 1-4 pages within the time limit.
// This value is high enough to not block updates on tables with many partitions and low enough to not let costs
// spiral out of control when we encounter network outage/latency or other such rare failure scenarios.
const maxNumCalls = 1000

// HandleSyncTableEvent starts or continues a gluetasks.SyncTablePartitions task.
// nolint: nakedret
func HandleSyncTableEvent(ctx context.Context, event *SyncTableEvent) (err error) {
	log := lambdalogger.FromContext(ctx)
	log = log.With(
		zap.String("traceId", event.TraceID),
		zap.Int("numCalls", event.NumCalls),
	)
	sync := event.SyncTablePartitions
	sync.NumWorkers = runtime.NumCPU() + 1
	// defer invoking continuation
	defer func() {
		if err == nil {
			return
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return
		}
		// protect against infinite recursion
		numCalls := event.NumCalls + 1
		if numCalls > maxNumCalls {
			log.Error("max calls exceeded",
				zap.String("table", event.TableName),
				zap.String("database", event.DatabaseName),
				zap.String("token", sync.NextToken),
				zap.Error(err),
			)
			return
		}

		log.Debug("continuing sync", zap.String("token", sync.NextToken))
		// We use context.Background to limit the probability of missing the continuation request
		err = invokeEvent(context.Background(), lambdaClient, &DataCatalogEvent{
			SyncTablePartitions: &SyncTableEvent{
				SyncTablePartitions: sync,
				NumCalls:            numCalls,
				TraceID:             event.TraceID, // keep the original trace id
			},
		})
	}()

	// Reserve some time for continuing the task in a new lambda invocation
	// If the timeout too short we resort to using context.Background to send the request outside of the
	// lambda handler time slot.
	if deadline, ok := ctx.Deadline(); ok {
		const gracefulExitTimeout = time.Second
		timeout := time.Until(deadline)
		if timeout > gracefulExitTimeout {
			timeout = timeout - gracefulExitTimeout
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
	}

	err = sync.Run(ctx, glueClient, log)
	stats := sync.Stats
	log.Debug("sync table complete", zap.Any("stats", &stats), zap.Error(err))
	return
}
