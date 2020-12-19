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

	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// SyncDatabasePartitionsEvent is a request to sync all database partitions
type SyncDatabasePartitionsEvent struct {
	// An identifier to use in order to keep track of all 'child' Lambda invocations for this sync.
	TraceID string
	// Which databases to sync
	DatabaseNames []string
	// Which log types to sync
	LogTypes []string
	// If set to true the sync will only scan for updates and will not modify Glue partitions
	DryRun bool
}

// HandleSyncDatabasePartitionsEvent handles a full database sync by invoking all required table sync events in the background
func (h *LambdaHandler) HandleSyncDatabasePartitionsEvent(ctx context.Context, event *SyncDatabasePartitionsEvent) error {
	log := lambdalogger.FromContext(ctx)
	log = log.With(
		zap.String("traceId", event.TraceID),
		zap.Bool("dryRun", event.DryRun),
	)
	var tableEvents []*SyncTableEvent
	for _, logType := range event.LogTypes {
		for _, dbName := range event.DatabaseNames {
			if !pantherdb.IsInDatabase(logType, dbName) {
				// If a logtype is notpresent in the given database, skip
				continue
			}
			tableEvents = append(tableEvents, &SyncTableEvent{
				TraceID: event.TraceID,
				SyncTablePartitions: gluetasks.SyncTablePartitions{
					DryRun:       event.DryRun,
					TableName:    pantherdb.TableName(logType),
					DatabaseName: dbName,
				},
			})
		}
	}
	numTasks := 0
	var err error
	for _, event := range tableEvents {
		sendErr := sendEvent(ctx, h.SQSClient, h.QueueURL, sqsTask{
			SyncTablePartitions: event,
		})
		err = multierr.Append(err, sendErr)
		if sendErr != nil {
			log.Error("failed to invoke table sync", zap.String("table", event.TableName), zap.Error(err))
			continue
		}
		numTasks++
	}
	log.Info("database sync started", zap.Int("numTables", len(tableEvents)), zap.Int("numTasks", numTasks))
	return nil
}
