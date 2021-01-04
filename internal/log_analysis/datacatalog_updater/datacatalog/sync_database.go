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

	"github.com/pkg/errors"
	"go.uber.org/multierr"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/stringset"
)

type SyncDatabaseEvent struct {
	TraceID          string
	RequiredLogTypes []string
}

func (h *LambdaHandler) HandleSyncDatabaseEvent(ctx context.Context, event *SyncDatabaseEvent) (err error) {
	for db, desc := range pantherdb.Databases {
		if err := awsglue.EnsureDatabase(ctx, h.GlueClient, db, desc); err != nil {
			return errors.Wrapf(err, "failed to create database %s", db)
		}
	}
	// We combine the deployed log types with the ones required by all active sources
	// This way if new code for sources requires more log types on upgrade, they are added
	var syncLogTypes []string
	{
		deployedLogTypes, err := h.fetchAllDeployedLogTypes(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to fetch deployed log types")
		}
		syncLogTypes = stringset.Concat(deployedLogTypes, event.RequiredLogTypes)
	}

	// this can return non-fatal errors we want to return to caller but but not stop
	var createTablesErr error
	if createTablesErr = h.createOrUpdateTablesForLogTypes(ctx, syncLogTypes); HasFatalCreateTableError(createTablesErr) {
		err = errors.Wrap(err, "failed to update tables for deployed log types")
		return err
	}
	defer func() { // add in at the end for caller
		err = multierr.Combine(err, createTablesErr)
	}()

	// this can return non-fatal errors we want to return to caller but but not stop
	var createViewsErr error
	if createViewsErr = h.createOrReplaceViewsForAllDeployedLogTables(ctx); HasFatalCreateTableError(createViewsErr) {
		err = errors.Wrap(err, "failed to update athena views for deployed log types")
		return err
	}
	defer func() { // add in at the end for caller
		err = multierr.Combine(err, createViewsErr)
	}()

	var syncError error
	if syncError = h.sendPartitionSync(ctx, event.TraceID, syncLogTypes); syncError != nil {
		err = errors.Wrap(err, "failed to send sync partitions event")
		return err
	}

	return err
}

// sendPartitionSync triggers a database partition sync by sending an event to the queue.
// If no TraceID is provided this function will try to use the AWS request id.
func (h *LambdaHandler) sendPartitionSync(ctx context.Context, syncTraceID string, logTypes []string) error {
	return sendEvent(ctx, h.SQSClient, h.QueueURL, sqsTask{
		SyncDatabasePartitions: &SyncDatabasePartitionsEvent{
			TraceID:  traceIDFromContext(ctx, syncTraceID),
			LogTypes: logTypes,
			DatabaseNames: []string{
				pantherdb.LogProcessingDatabase,
				pantherdb.RuleMatchDatabase,
				pantherdb.RuleErrorsDatabase,
				pantherdb.CloudSecurityDatabase,
			},
		},
	})
}
