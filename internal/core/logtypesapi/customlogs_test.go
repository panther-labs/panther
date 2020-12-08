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

	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestAPI_PutCustomLog(t *testing.T) {
	integration := &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			IntegrationType:  models.IntegrationTypeAWS3,
			S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "", Logtypes: []string{"Custom.InUse"}}},
		},
	}
	marshaledResult, err := jsoniter.Marshal([]*models.SourceIntegration{integration})
	require.NoError(t, err)
	lambdaOutput := &lambda.InvokeOutput{
		Payload: marshaledResult,
	}
	lambdaMock := &testutils.LambdaMock{}
	lambdaMock.On("Invoke", mock.Anything).Return(lambdaOutput, nil)
	api := logtypesapi.LogTypesAPI{
		Database:     logtypesapi.NewInMemory(),
		LambdaClient: lambdaMock,
	}
	ctx := context.Background()
	assert := require.New(t)
	expect := logtypesapi.CustomLog{
		Description:  "An example custom log type",
		ReferenceURL: "https://example.com/docs",
		LogSpec:      `{"version": 0, "fields": [{"name": "foo", "type": "string"}]}`,
	}
	reply, err := api.PutCustomLog(ctx, &logtypesapi.PutCustomLogInput{
		Revision:  0,
		LogType:   "Custom.Event",
		CustomLog: expect,
	})
	assert.NoError(err)
	assert.NotNil(reply)
	assert.Nil(reply.Error)
	record := reply.Result
	assert.Equal(&expect, &record.CustomLog)
	assert.Equal(int64(1), record.Revision)

	{
		reply, err := api.GetCustomLog(ctx, &logtypesapi.GetCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 1,
		})
		assert.NoError(err)
		assert.NotNil(reply)
		assert.Nil(reply.Error)
		record := reply.Result
		assert.Equal(&expect, &record.CustomLog)
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
		assert.Equal(&expect, &record.CustomLog)
		assert.Equal(int64(1), record.Revision)
	}

	{
		reply, err := api.GetCustomLog(ctx, &logtypesapi.GetCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 2,
		})
		assert.Nil(err)
		assert.Nil(reply.Result)
		assert.NotNil(reply.Error)
		assert.Equal(logtypesapi.ErrNotFound, reply.Error.Code)
	}

	expect = logtypesapi.CustomLog{
		Description:  "An example custom log type",
		ReferenceURL: "https://example.com/docs/v2",
		LogSpec:      `{"version": 0, "fields": [{"name": "bar", "type": "string"}]}`,
	}
	reply, err = api.PutCustomLog(ctx, &logtypesapi.PutCustomLogInput{
		Revision:  1,
		LogType:   "Custom.Event",
		CustomLog: expect,
	})
	assert.NoError(err)
	assert.NotNil(reply)
	assert.NotNil(reply.Error)

	{
		reply, err := api.DelCustomLog(ctx, &logtypesapi.DelCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 2,
		})
		assert.NoError(err)
		assert.NotNil(reply.Error)
		assert.Equal(reply.Error.Code, logtypesapi.ErrRevisionConflict)
	}
	{
		reply, err := api.DelCustomLog(ctx, &logtypesapi.DelCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 1,
		})
		assert.NoError(err)
		assert.Nil(reply.Error)
	}
	{
		reply, err := api.DelCustomLog(ctx, &logtypesapi.DelCustomLogInput{
			LogType:  "Custom.Event",
			Revision: 1,
		})
		assert.NoError(err)
		assert.NotNil(reply.Error)
		assert.Equal(reply.Error.Code, logtypesapi.ErrRevisionConflict)
	}
	{
		reply, err := api.DelCustomLog(ctx, &logtypesapi.DelCustomLogInput{
			LogType:  "Custom.InUse",
			Revision: 1,
		})
		assert.NoError(err)
		assert.NotNil(reply.Error)
		assert.Equal(reply.Error.Code, logtypesapi.ErrInUse)
	}
	lambdaMock.AssertExpectations(t)
}

// Enterprise-only stubs

// nolint:lll
func (ListAvailableAPI) GetCustomLog(_ context.Context, _ string, _ int64) (*logtypesapi.CustomLogRecord, error) {
	panic("implement me")
}

// nolint:lll
func (ListAvailableAPI) CreateCustomLog(_ context.Context, _ string, _ *logtypesapi.CustomLog) (*logtypesapi.CustomLogRecord, error) {
	panic("implement me")
}

// nolint:lll
func (ListAvailableAPI) UpdateCustomLog(_ context.Context, _ string, _ int64, _ *logtypesapi.CustomLog) (*logtypesapi.CustomLogRecord, error) {
	panic("implement me")
}

// nolint:lll
func (ListAvailableAPI) DeleteCustomLog(_ context.Context, _ string, _ int64) error {
	panic("implement me")
}

// nolint:lll
func (ListAvailableAPI) BatchGetCustomLogs(ctx context.Context, ids ...string) ([]*logtypesapi.CustomLogRecord, error) {
	panic("implement me")
}
