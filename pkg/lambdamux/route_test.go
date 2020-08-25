package lambdamux

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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type testAPI struct {
}

func (*testAPI) HandleFoo(ctx context.Context) error {
	return nil
}

func TestStructRoutes(t *testing.T) {
	assert := require.New(t)
	routes, err := StructRoutes(DefaultHandlerPrefix, &testAPI{})
	assert.NoError(err)
	assert.Len(routes, 1)
	assert.Nil(routes[0].input)
	assert.Nil(routes[0].output)
	assert.True(routes[0].withError)
	assert.True(routes[0].withContext)
	assert.Equal(1, routes[0].method.Type().NumIn())

	mux := Mux{}
	mux.HandleRoutes(routes...)
	mux.MustHandleStructs(DefaultHandlerPrefix, &testAPI{})
	output, err := mux.HandleRaw(context.Background(), json.RawMessage(`{"Foo":{}}`))
	assert.NoError(err)
	assert.Equal("{}", string(output))
}
