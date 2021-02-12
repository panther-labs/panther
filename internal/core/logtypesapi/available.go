package logtypesapi

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
	"sort"
)

// ListAvailableLogTypes lists all available log type ids
func (api *LogTypesAPI) ListAvailableLogTypes(ctx context.Context) (*AvailableLogTypes, error) {
	logTypes := make([]string, 0)
	scan := func(r *SchemaRecord) bool {
		if !r.Disabled {
			logTypes = append(logTypes, r.Name)
		}
		return true
	}
	if err := api.Database.ScanSchemas(ctx, scan); err != nil {
		return nil, err
	}
	// Sort available log types by name
	sort.Strings(logTypes)

	return &AvailableLogTypes{
		LogTypes: logTypes,
	}, nil
}

type AvailableLogTypes struct {
	LogTypes []string `json:"logTypes"`
}

// ListDeletedCustomLogs lists all deleted log type ids
func (api *LogTypesAPI) ListDeletedCustomLogs(ctx context.Context) (*DeletedCustomLogs, error) {
	logTypes := make([]string, 0)
	scan := func(r *SchemaRecord) bool {
		if r.IsCustom() && r.Disabled {
			logTypes = append(logTypes, r.Name)
		}
		return true
	}
	if err := api.Database.ScanSchemas(ctx, scan); err != nil {
		return nil, err
	}
	// Sort deleted log types by name
	sort.Strings(logTypes)
	return &DeletedCustomLogs{
		LogTypes: logTypes,
	}, nil
}

type DeletedCustomLogs struct {
	LogTypes []string  `json:"logTypes,omitempty" description:"A list of ids of deleted log types (omitted if an error occurred)"`
	Error    *APIError `json:"error,omitempty" description:"An error that occurred while fetching the list"`
}
