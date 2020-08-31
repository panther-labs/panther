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

func TestBatch(t *testing.T) {
	mux := Mux{}
	type Payload struct {
		Foo string `json:"foo"`
	}
	type Reply struct {
		Bar string `json:"bar,omitempty"`
		Baz string `json:"baz,omitempty"`
	}

	mux.MustHandle("bar", func(payload *Payload) (*Reply, error) {
		return &Reply{Bar: payload.Foo}, nil
	})
	mux.MustHandle("baz", func(payload *Payload) (*Reply, error) {
		return &Reply{Baz: payload.Foo}, nil
	})
	ctx := context.Background()
	assert := require.New(t)
	{
		reply, err := mux.Invoke(ctx, []byte(`[{"bar":{"foo":"bar"}},{"baz":{"foo":"baz"}}]`))
		assert.NoError(err)
		assert.JSONEq(`[{"bar":"bar"},{"baz":"baz"}]`, string(reply))
	}
}
