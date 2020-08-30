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
	"testing"

	"github.com/stretchr/testify/require"
)

type TestAPI struct{}

type Foo struct {
	Bar string `json:"bar"`
}

func (*TestAPI) GetFoo() *Foo {
	return &Foo{
		Bar: "baz",
	}
}
func (*TestAPI) GetFooWithContext(_ context.Context) *Foo {
	return &Foo{
		Bar: "baz",
	}
}

func TestMux(t *testing.T) {
	mux := Mux{}
	ctx := context.Background()
	assert := require.New(t)
	mux.MustHandleMethods(&TestAPI{})
	{
		payload := []byte(`{"GetFoo":{}}`)
		reply, err := mux.Invoke(ctx, payload)
		assert.NoError(err)
		assert.JSONEq(`{"bar":"baz"}`, string(reply))
	}
	{
		payload := []byte(`{"GetFooWithContext":{}}`)
		reply, err := mux.Invoke(ctx, payload)
		assert.NoError(err)
		assert.JSONEq(`{"bar":"baz"}`, string(reply))
	}
}
