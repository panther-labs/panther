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
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"

	"github.com/pkg/errors"
)

type UpdateTablesEvent struct {
	LogType string
	TraceID string
}

func (h *LambdaHandler) HandleUpdateTablesEvent(ctx context.Context, event *UpdateTablesEvent) error {
	// We need to fetch a fresh entry for this log type
	h.ClearLogTypeCache(event.LogType)
	logTypes := []string{event.LogType}
	if err := h.updateTablesForLogTypes(ctx, logTypes); err != nil {
		return errors.Wrap(err, "failed to update tables for deployed log types")
	}
	if err := h.createOrReplaceViewsForAllDeployedLogTables(ctx); err != nil {
		return errors.Wrap(err, "failed to update athena views for deployed log types")
	}
	if err := h.sendPartitionSync(ctx, event.TraceID, logTypes); err != nil {
		return errors.Wrap(err, "failed to send sync partitions event")
	}
	return nil
}

func (h *LambdaHandler) updateTablesForLogTypes(ctx context.Context, logTypes []string) error {
	// We map the log types to their 'base' log tables.
	tables, err := resolveTables(ctx, h.Resolver, logTypes...)
	if err != nil {
		return err
	}
	for i, table := range tables {
		logType := logTypes[i]
		// FIXME: this is confusing, the gluetables package should NOT be expanding table metadata based on hard-wired logic
		// This logic should be left to a 'central' module such as `pantherdb` and use 'abstract' Database/Table/Partition structs
		// The glue-relevant actions can be abstracted to:
		// - CreateDatabaseIfNotExists
		// - CreateTableIfNotExists
		// - CreateOrReplaceTable
		// - CreatePartitionIfNotExists
		// - CreateOrReplacePartition
		// - ScanDatabases
		// - ScanDatabaseTables
		// - ScanTablePartitions
		// These actions should be part of an interface that manages the data lake backend.
		// We need methods that use abstract Database/Table/Partition structs that can contain info for all backends.
		if _, err := gluetables.UpdateTablesIfExist(ctx, h.GlueClient, h.ProcessedDataBucket, table); err != nil {
			return errors.Wrapf(err, "failed to create or update tables for log type %q", logType)
		}
	}
	return nil
}
