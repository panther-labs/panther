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

	"go.uber.org/zap"
)

// ListAvailableLogTypes lists all available log type ids
func (api *LogTypesAPI) ListAvailableLogTypes(ctx context.Context) (*AvailableLogTypes, error) {
	logTypes, err := api.Database.IndexLogTypes(ctx)
	if err != nil {
		return nil, err
	}
	if api.NativeLogTypes != nil {
		native := api.NativeLogTypes()
		L(ctx).Debug(`merging native log types with database log types`,
			zap.Strings(`external`, logTypes),
			zap.Strings(`native`, native),
		)
		logTypes = appendDistinct(logTypes, native...)
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

func appendDistinct(dst []string, src ...string) []string {
skip:
	for _, s := range src {
		for _, d := range dst {
			if d == s {
				continue skip
			}
		}
		dst = append(dst, s)
	}
	return dst
}

// ListDeletedCustomLogs lists all deleted log type ids
func (api *LogTypesAPI) ListDeletedCustomLogs(ctx context.Context) (*DeletedCustomLogs, error) {
	logTypes, err := api.Database.ListDeletedLogTypes(ctx)
	if err != nil {
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
