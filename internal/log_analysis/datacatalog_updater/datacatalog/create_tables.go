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

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
)

type CreateTablesEvent struct {
	LogTypes []string
}

func (h *LambdaHandler) HandleCreateTablesEvent(ctx context.Context, event *CreateTablesEvent) error {
	if err := h.createOrUpdateTablesForLogTypes(ctx, event.LogTypes); err != nil {
		return err
	}
	if err := h.createOrReplaceViewsForAllDeployedTables(ctx); err != nil {
		return errors.Wrap(err, "failed to update views")
	}
	return nil
}

func (h *LambdaHandler) createOrUpdateTablesForLogTypes(ctx context.Context, logTypes []string) error {
	// We map the log types to their 'base' log tables.
	tables, err := resolveLogTables(ctx, h.Resolver, logTypes...)
	if err != nil {
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

func (h *LambdaHandler) createOrReplaceViewsForAllDeployedTables(ctx context.Context) error {
	// We fetch the tables again to avoid any possible race condition
	deployedLogTypes, err := h.fetchAllDeployedLogTypes(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to fetch deployed log types")
	}
	// We map the deployed log types to their 'base' log tables.
	deployedLogTables, err := resolveLogTables(ctx, h.Resolver, deployedLogTypes...)
	if err != nil {
		return errors.Wrap(err, "failed to resolve tables for logtypes")
	}
	// update the views for *all* tables based on the log tables.
	// FIXME: this is confusing, the athenaviews package should not be creating views by expanding table metadata based on hard-wired logic
	if err := athenaviews.CreateOrReplaceViews(h.AthenaClient, h.AthenaWorkgroup, deployedLogTables); err != nil {
		return errors.Wrap(err, "failed to update athena views")
	}
	return nil
}

func (h *LambdaHandler) fetchAllDeployedLogTypes(ctx context.Context) ([]string, error) {
	available, err := h.ListAvailableLogTypes(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list available log types")
	}
	return gluetables.DeployedLogTypes(ctx, h.GlueClient, available)
}

func resolveLogTables(ctx context.Context, r logtypes.Resolver, names ...string) ([]*awsglue.GlueTableMetadata, error) {
	var out []*awsglue.GlueTableMetadata
	for _, name := range names {
		entry, err := r.Resolve(ctx, name)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, errors.Errorf("unresolved log type %q", name)
		}
		eventSchema := entry.Schema()
		desc := entry.Describe()
		meta := awsglue.NewGlueTableMetadata(models.LogData, desc.Name, desc.Description, awsglue.GlueTableHourly, eventSchema)
		out = append(out, meta)
	}
	return out, nil
}
