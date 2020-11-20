package datacatalog

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

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// Max number of calls for a single table sync.
// Each year of hourly partitions is 8760 partitions.
// Avg page size seems to vary between 100-200 partitions per page.
// We expect ~100 pages per year of data.
// Each invocation should handle 1-4 pages within the time limit.
// This value is high enough to not block updates on tables with many partitions and low enough to not let costs
// spiral out of control when we encounter network outage/latency or other such rare failure scenarios.
const maxNumCalls = 1000

// Max number of retries on the same token without progress
const maxConsecutiveSyncTimeouts = 5

// Set the number of parallel partition updates
const numSyncWorkersPerTable = 8

// SyncTableEvent initializes or continues a gluetasks.SyncTablePartitions task
type SyncTableEvent struct {
	// Use a common trace id (the SyncDatabase request id) for all events triggered by a sync event.
	// This is used in all logging done by the SyncTablePartitions task to be able to trace all lambda invocations
	// back to their original SyncDatabase request.
	TraceID string
	// NumCalls keeps track of the number of recursive calls for the specific sync table event.
	// It acts as a guard against infinite recursion.
	NumCalls int
	// NumTimeouts keeps track of how many times the last token was retried because of timeout.
	NumTimeouts int
	// Embed the full sync table partitions task state
	// This allows us to continue the task by recursively calling the lambda.
	// The task carries all status information over
	gluetasks.SyncTablePartitions
}

// HandleSyncTableEvent starts or continues a gluetasks.SyncTablePartitions task.
// nolint: nakedret
func (h *LambdaHandler) HandleSyncTableEvent(ctx context.Context, event *SyncTableEvent) error {
	// Reserve some time for continuing the task in a new lambda invocation
	// If the timeout too short we resort to using context.Background to send the request outside of the
	// lambda handler time slot.
	if deadline, ok := ctx.Deadline(); ok {
		const gracefulExitTimeout = time.Minute
		timeout := time.Until(deadline)
		if timeout > gracefulExitTimeout {
			timeout = timeout - gracefulExitTimeout
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
	}

	logger := lambdalogger.FromContext(ctx).With(
		zap.String("traceId", event.TraceID),
		zap.Int("numCalls", event.NumCalls),
		zap.Int("numTimeouts", event.NumTimeouts),
	)
	sync := event.SyncTablePartitions
	sync.NumWorkers = numSyncWorkersPerTable

	err := sync.Run(ctx, h.GlueClient, logger)

	// We add these fields after Run() to avoid duplicate fields in the log output of sync.Run()
	logger = logger.With(
		zap.String("table", event.TableName),
		zap.String("database", event.DatabaseName),
	)
	if err == nil {
		logger.Info("sync complete", zap.Any("stats", &sync.Stats))
		return nil
	}

	logger.Info("sync progress", zap.Any("stats", &sync.Stats))

	// We only continue our work if failure was due to timeout
	if errors.Is(err, context.DeadlineExceeded) {
		nextEvent, nextErr := buildNextSyncEvent(event, &sync)
		if nextErr != nil {
			return nextErr
		}

		// We use context.Background to limit the probability of missing the continuation request
		if continueErr := sendEvent(context.Background(), h.SQSClient, h.QueueURL, *nextEvent); continueErr != nil {
			err = errors.WithMessage(continueErr, "sync failed to continue")
		}
	}

	if err != nil {
		// We log the error here to take advantage of zap fields for tracing
		logger.Error("sync failed", zap.Error(err))
		// Add some helpful message to the returned error
		return errors.WithMessagef(err, "sync %s.%s failed", event.DatabaseName, event.TableName)
	}

	return nil
}

func buildNextSyncEvent(event *SyncTableEvent, sync *gluetasks.SyncTablePartitions) (*sqsTask, error) {
	numTimeouts := 0
	if sync.NextToken != "" && sync.NextToken == event.NextToken {
		// Deadline reached without any progress
		numTimeouts = event.NumTimeouts + 1
	}
	if numTimeouts > maxConsecutiveSyncTimeouts {
		return nil, errors.Errorf("no progress after %d retries", numTimeouts)
	}
	// protect against infinite recursion
	numCalls := event.NumCalls + 1
	if numCalls > maxNumCalls {
		return nil, errors.Errorf("sync did not complete after %d lambdsa calls", numCalls)
	}

	return &sqsTask{
		SyncTablePartitions: &SyncTableEvent{
			SyncTablePartitions: *sync,
			NumCalls:            numCalls,
			NumTimeouts:         numTimeouts,
			TraceID:             event.TraceID, // keep the original trace id
		},
	}, nil
}
