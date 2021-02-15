package logtypesapi_test

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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
)

func TestAPI_ListAvailableLogTypes(t *testing.T) {
	assert := require.New(t)
	ctx := context.Background()
	api := logtypesapi.LogTypesAPI{
		Database: ListAvailableAPI{"bar", "baz", "foo", "aaa"},
	}

	actual, _ := api.ListAvailableLogTypes(ctx)
	assert.Equal(&logtypesapi.AvailableLogTypes{
		LogTypes: []string{"aaa", "bar", "baz", "foo"},
	}, actual)
}

var _ logtypesapi.SchemaDatabase = (ListAvailableAPI)(nil)

type ListAvailableAPI []string

// nolint:lll
func (l ListAvailableAPI) GetSchema(_ context.Context, _ string) (*logtypesapi.SchemaRecord, error) {
	panic("implement me")
}

// nolint:lll
func (l ListAvailableAPI) PutSchema(_ context.Context, _ string, _ *logtypesapi.SchemaRecord) (*logtypesapi.SchemaRecord, error) {
	panic("implement me")
}

// nolint:lll
func (l ListAvailableAPI) ScanSchemas(_ context.Context, scan logtypesapi.ScanSchemaFunc) error {
	for _, name := range l {
		r := logtypesapi.SchemaRecord{
			Name: name,
		}
		if !scan(&r) {
			return nil
		}
	}
	return nil
}
