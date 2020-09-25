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

type SyncTableEvent struct {
	TraceID  string
	NumCalls int
	gluetasks.SyncTablePartitions
}

const maxNumCalls = 1000

// nolint: nakedret
func HandleSyncTable(ctx context.Context, event *SyncTableEvent) (err error) {
	nextToken := event.NextToken
	log := lambdalogger.FromContext(ctx)
	log = log.With(
		zap.String("traceId", event.TraceID),
		zap.Int("numCalls", event.NumCalls),
	)
	syncTask := event.SyncTablePartitions
	syncTask.NumWorkers = runtime.NumCPU() + 1
	// defer invoking continuation
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) && nextToken != "" {
			numCalls := event.NumCalls + 1
			// protect against infinite recursion
			if numCalls > maxNumCalls {
				log.Error("max calls exceeded",
					zap.String("table", event.TableName),
					zap.String("database", event.DatabaseName),
					zap.String("token", nextToken),
					zap.Error(err),
				)
				return
			}

			zap.L().Debug("continuing sync", zap.String("token", nextToken))
			// We use context.Background to limit the probability of missing the request
			err = invokeEvent(context.Background(), lambdaClient, &DataCatalogEvent{
				SyncTablePartitions: &SyncTableEvent{
					SyncTablePartitions: syncTask,
					NumCalls:            numCalls,
					TraceID:             event.TraceID,
				},
			})
		}
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

	err = syncTask.Run(ctx, glueClient, log)
	stats := syncTask.Stats
	log.Debug("sync table complete", zap.Any("stats", &stats), zap.Error(err))
	return
}
