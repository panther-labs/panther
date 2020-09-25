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

	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
)

type SyncEvent struct {
	TraceID       string
	DatabaseNames []string
	LogTypes      []string
	DryRun        bool
}

func HandleSyncDatabase(ctx context.Context, event *SyncEvent) error {
	log := zap.L()
	log = log.With(
		zap.String("traceId", event.TraceID),
		zap.Bool("dryRun", event.DryRun),
	)
	tableEvents := []*SyncTableEvent{}
	for _, dbName := range event.DatabaseNames {
		afterTableCreateTime := dbName != awsglue.LogProcessingDatabaseName
		for _, logType := range event.LogTypes {
			tblName := awsglue.GetTableName(logType)
			tableEvents = append(tableEvents, &SyncTableEvent{
				TraceID: event.TraceID,
				SyncTablePartitions: gluetasks.SyncTablePartitions{
					DryRun:               event.DryRun,
					TableName:            tblName,
					DatabaseName:         dbName,
					AfterTableCreateTime: afterTableCreateTime,
				},
			})
		}
	}
	numTasks := 0
	var err error
	for _, event := range tableEvents {
		invokeErr := invokeEvent(ctx, lambdaClient, &DataCatalogEvent{
			SyncTablePartitions: event,
		})
		err = multierr.Append(err, invokeErr)
		if invokeErr != nil {
			log.Error("failed to invoke table sync", zap.String("table", event.TableName), zap.Error(err))
			continue
		}
		numTasks++
	}
	log.Info("database sync started", zap.Int("numTables", len(tableEvents)), zap.Int("numTasks", numTasks))
	return nil
}
