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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
)

func TestAPI_PutCustomLog(t *testing.T) {
	numDataCatalogCalls := 0
	api := logtypesapi.LogTypesAPI{
		Database: logtypesapi.NewInMemory(),
		LogTypesInUse: func(ctx context.Context) ([]string, error) {
			return []string{"Custom.InUse"}, nil
		},
		UpdateDataCatalog: func(ctx context.Context, logType string, from, to []logschema.FieldSchema) error {
			numDataCatalogCalls++
			return nil
		},
	}
	ctx := context.Background()
	assert := require.New(t)
	expect := logtypesapi.SchemaUpdate{
		Description:  "An example custom log type",
		ReferenceURL: "https://example.com/docs",
		Spec:         `{"version": 0, "fields": [{"name": "foo", "type": "string"}]}`,
	}
	reply, err := api.PutCustomLog(ctx, &logtypesapi.PutCustomLogInput{
		Revision:     0,
		LogType:      "Custom.Event",
		SchemaUpdate: expect,
	})
	assert.NoError(err)
	assert.NotNil(reply)
	assert.Nil(reply.Error)
	record := reply.Result
	assert.Equal(&logtypesapi.SchemaUpdate{
		Description:  record.Description,
		ReferenceURL: record.ReferenceURL,
		Spec:         record.Spec,
	}, &record.SchemaUpdate)
	assert.Equal(int64(1), record.Revision)
	assert.Equal(1, numDataCatalogCalls)
	{
		reply, err := api.GetCustomLog(ctx, &logtypesapi.GetCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 1,
		})
		assert.NoError(err)
		assert.NotNil(reply)
		assert.Nil(reply.Error)
		record := reply.Result
		assert.Equal(&expect, &record.SchemaUpdate)
		assert.Equal(int64(1), record.Revision)
	}
	{
		reply, err := api.GetCustomLog(ctx, &logtypesapi.GetCustomLogInput{
			LogType: "Custom.Event",
		})
		assert.NoError(err)
		assert.NotNil(reply)
		assert.Nil(reply.Error)
		record := reply.Result
		assert.Equal(&expect, &record.SchemaUpdate)
		assert.Equal(int64(1), record.Revision)
	}

	{
		reply, err := api.GetCustomLog(ctx, &logtypesapi.GetCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 2,
		})
		assert.NotNil(err)
		assert.Nil(reply)
		assert.Equal(logtypesapi.ErrNotFound, logtypesapi.AsAPIError(err).Code)
	}

	expect = logtypesapi.SchemaUpdate{
		Description:  "An example custom log type",
		ReferenceURL: "https://example.com/docs/v2",
		Spec:         `{"version": 0, "fields": [{"name": "bar", "type": "string"}]}`,
	}
	reply, err = api.PutCustomLog(ctx, &logtypesapi.PutCustomLogInput{
		Revision:     1,
		LogType:      "Custom.Event",
		SchemaUpdate: expect,
	})
	assert.Error(err)
	assert.Nil(reply)
	assert.Equal(logtypesapi.ErrInvalidUpdate, logtypesapi.AsAPIError(err).Code)

	{
		reply, err := api.DelCustomLog(ctx, &logtypesapi.DelCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 2,
		})
		assert.NoError(err)
		assert.Nil(reply.Error)
		assert.Equal(2, numDataCatalogCalls)
	}
	{
		reply, err := api.DelCustomLog(ctx, &logtypesapi.DelCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 1,
		})
		assert.NoError(err)
		assert.Nil(reply.Error)
		assert.Equal(3, numDataCatalogCalls)
	}
	{
		reply, err := api.DelCustomLog(ctx, &logtypesapi.DelCustomLogInput{
			LogType:  "Custom.InUse",
			Revision: 1,
		})
		assert.Error(err)
		assert.Nil(reply)
		assert.Equal(logtypesapi.ErrInUse, logtypesapi.AsAPIError(err).Code)
	}
}
