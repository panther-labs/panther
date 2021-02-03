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
func (l ListAvailableAPI) ScanSchemas(ctx context.Context, scan logtypesapi.ScanSchemaFunc) error {
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

// nolint:lll
func (l ListAvailableAPI) CreateUserSchema(ctx context.Context, id string, upd logtypesapi.SchemaUpdate) (*logtypesapi.SchemaRecord, error) {
	panic("implement me")
}

// nolint:lll
func (l ListAvailableAPI) GetSchema(ctx context.Context, id string, revision int64) (*logtypesapi.SchemaRecord, error) {
	panic("implement me")
}

// nolint:lll
func (l ListAvailableAPI) UpdateUserSchema(ctx context.Context, id string, rev int64, upd logtypesapi.SchemaUpdate) (*logtypesapi.SchemaRecord, error) {
	panic("implement me")
}

// nolint:lll
func (l ListAvailableAPI) UpdateManagedSchema(ctx context.Context, id string, rev int64, release string, upd logtypesapi.SchemaUpdate) (*logtypesapi.SchemaRecord, error) {
	panic("implement me")
}

// nolint:lll
func (l ListAvailableAPI) ToggleSchema(ctx context.Context, id string, enabled bool) error {
	panic("implement me")
}

// nolint:lll
func (l ListAvailableAPI) BatchGetSchemas(ctx context.Context, ids ...string) ([]*logtypesapi.SchemaRecord, error) {
	panic("implement me")
}
