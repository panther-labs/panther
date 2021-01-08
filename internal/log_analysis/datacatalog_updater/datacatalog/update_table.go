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

	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

type UpdateTablesEvent struct {
	LogType string
	TraceID string
}

func (h *LambdaHandler) HandleUpdateTablesEvent(ctx context.Context, event *UpdateTablesEvent) error {
	entry, err := h.Resolver.Resolve(ctx, event.LogType)
	if err != nil {
		return err
	}
	tbl := tableForEntry(entry)
	updated, err := tbl.UpdateTableIfExists(ctx, h.GlueClient, h.ProcessedDataBucket)
	if err != nil {
		return err
	}
	// If the table was not updated, it means that it does not exist yet.
	// Tables are only created when used in sources.
	// It is possible that a schema was updated before assigning it to a source.
	if !updated {
		return nil
	}
	if typ := pantherdb.DataType(event.LogType); typ != pantherdb.CloudSecurity {
		if _, err := tbl.RuleTable().UpdateTableIfExists(ctx, h.GlueClient, h.ProcessedDataBucket); err != nil {
			return err
		}
		if _, err := tbl.RuleErrorTable().UpdateTableIfExists(ctx, h.GlueClient, h.ProcessedDataBucket); err != nil {
			return err
		}
	}
	if err := h.createOrReplaceViewsForAllDeployedLogTables(ctx); err != nil {
		return errors.Wrap(err, "failed to update athena views for deployed log types")
	}
	if err := h.sendPartitionSync(ctx, event.TraceID, []string{event.LogType}); err != nil {
		return errors.Wrap(err, "failed to send sync partitions event")
	}
	return nil
}
