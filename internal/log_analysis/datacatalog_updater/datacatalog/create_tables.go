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

	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

type CreateTablesEvent struct {
	LogTypes []string
}

func (h *LambdaHandler) HandleCreateTablesEvent(ctx context.Context, event *CreateTablesEvent) error {
	if err := h.createOrUpdateTablesForLogTypes(ctx, event.LogTypes); HasFatalCreateTableError(err) {
		return err
	}
	return h.createOrReplaceViewsForAllDeployedLogTables(ctx)
}

func (h *LambdaHandler) createOrUpdateTablesForLogTypes(ctx context.Context, logTypes []string) error {
	// We map the log types to their 'base' log tables.
	tables, err := resolveTables(ctx, h.Resolver, logTypes...)
	if HasFatalCreateTableError(err) {
		return err
	}
	for i, table := range tables {
		// CreateOrUpdateGlueTables creates or updates *all* glue tables based on log tables.
		// FIXME: this is confusing, the gluetables package should not be expanding table metadata based on hard-wired logic
		if _, err := gluetables.CreateOrUpdateGlueTables(h.GlueClient, h.ProcessedDataBucket, table); err != nil {
			return errors.Wrapf(err, "failed to update tables for log type %q", logTypes[i])
		}
	}
	return nil
}

func (h *LambdaHandler) createOrReplaceViewsForAllDeployedLogTables(ctx context.Context) (err error) {
	// We fetch the tables again to avoid any possible race condition
	deployedLogTypes, err := h.fetchAllDeployedLogTypes(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to fetch deployed log types")
	}
	// We map the deployed log types to their 'base' log tables, errors are collected and not fatal
	deployedLogTables, resolveErrors := resolveTables(ctx, h.Resolver, deployedLogTypes...)
	defer func() { // add in at the end for caller
		err = multierr.Combine(err, resolveErrors)
	}()

	// update the views for *all* tables based on the log tables.
	// FIXME: this is confusing, the athenaviews package should not be creating views by expanding table metadata based on hard-wired logic
	if err = athenaviews.CreateOrReplaceLogViews(h.AthenaClient, h.AthenaWorkgroup, deployedLogTables); err != nil {
		return errors.Wrap(err, "failed to update athena views")
	}
	return err
}

func (h *LambdaHandler) fetchAllDeployedLogTypes(ctx context.Context) ([]string, error) {
	available, err := h.ListAvailableLogTypes(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list available log types")
	}
	return gluetables.DeployedLogTypes(ctx, h.GlueClient, available)
}

// Resolves the tables for the provided log types.
// Note that this will return only the BASE tables (tables in for panther_logs and panther_cloudsecurity databases) but not any
// downstream tables e.g. panther_rule_matches, panther_rule_errors
func resolveTables(ctx context.Context, r logtypes.Resolver, names ...string) (out []*awsglue.GlueTableMetadata, err error) {
	for _, name := range names {
		entry, resolveErr := r.Resolve(ctx, name)
		if resolveErr != nil || entry == nil { // don't fail whole operation if inconsistent data...
			err = multierr.Append(err,
				&UnResolvedLogTypeError{
					wrappedErr: errors.Wrapf(resolveErr, "unresolved log type: %s", name),
				})
			continue
		}
		eventSchema := entry.Schema()
		desc := entry.Describe()
		tableName := pantherdb.TableName(desc.Name)
		db := pantherdb.DatabaseName(pantherdb.GetDataType(name))
		meta := awsglue.NewGlueTableMetadata(db, tableName, desc.Description, awsglue.GlueTableHourly, eventSchema)
		out = append(out, meta)
	}
	return out, err
}

type UnResolvedLogTypeError struct {
	wrappedErr error
}

func (err *UnResolvedLogTypeError) Error() string {
	return err.wrappedErr.Error()
}

func IsUnResolvedLogType(err error) bool {
	if _, ok := err.(*UnResolvedLogTypeError); ok {
		return ok
	}
	return false
}

func HasFatalCreateTableError(err error) bool {
	for _, multiErr := range multierr.Errors(err) {
		if !IsUnResolvedLogType(multiErr) {
			return true
		}
	}
	return false
}
