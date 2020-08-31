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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDemuxKeyValue(t *testing.T) {
	mux := Mux{
		Demux: DemuxKeyValue(),
	}
	type Payload struct {
		Bar string `json:"bar"`
	}
	type Reply struct {
		Baz string `json:"baz"`
	}

	mux.MustHandle("foo", func(payload *Payload) (*Reply, error) {
		return &Reply{Baz: payload.Bar}, nil
	})

	ctx := context.Background()
	assert := require.New(t)
	{
		reply, err := mux.Invoke(ctx, []byte(`{"foo":{"bar":"baz"}}`))
		assert.NoError(err)
		assert.JSONEq(`{"baz":"baz"}`, string(reply))
	}
	{
		reply, err := mux.Invoke(ctx, []byte(`{"bar":{"bar":"baz"}}`))
		assert.True(errors.Is(err, ErrNotFound))
		assert.Nil(reply)
	}
}

func TestDemuxKeys(t *testing.T) {
	mux := Mux{
		Demux: DemuxKeys("method", "params"),
	}
	type Payload struct {
		Bar string `json:"bar"`
	}
	type Reply struct {
		Baz string `json:"baz"`
	}

	mux.MustHandle("foo", func(payload *Payload) (*Reply, error) {
		return &Reply{Baz: payload.Bar}, nil
	})

	ctx := context.Background()
	assert := require.New(t)
	{
		reply, err := mux.Invoke(ctx, []byte(`{"method": "foo", "params": {"bar":"baz"}}`))
		assert.NoError(err)
		assert.JSONEq(`{"baz":"baz"}`, string(reply))
	}
	{
		reply, err := mux.Invoke(ctx, []byte(`{"method": "bar", "params": {"bar":"baz"}}`))
		assert.True(errors.Is(err, ErrNotFound))
		assert.Nil(reply)
	}
	{
		reply, err := mux.Invoke(ctx, []byte(`{"method": "bar"}`))
		assert.True(errors.Is(err, ErrNotFound))
		assert.Nil(reply)
	}
	{
		reply, err := mux.Invoke(ctx, []byte(`{"params": {"bar":"baz"}}`))
		assert.True(errors.Is(err, ErrNotFound))
		assert.Nil(reply)
	}
}
func TestDemuxPeekKey(t *testing.T) {
	mux := Mux{
		Demux: DemuxPeekKey("method"),
	}
	type Payload struct {
		Bar string `json:"bar"`
	}
	type Reply struct {
		Baz string `json:"baz"`
	}

	mux.MustHandle("foo", func(payload *Payload) (*Reply, error) {
		return &Reply{Baz: payload.Bar}, nil
	})

	ctx := context.Background()
	assert := require.New(t)
	{
		reply, err := mux.Invoke(ctx, []byte(`{"method": "foo", "bar":"baz"}`))
		assert.NoError(err)
		assert.JSONEq(`{"baz":"baz"}`, string(reply))
	}
	{
		reply, err := mux.Invoke(ctx, []byte(`{"method": "bar", "bar":"baz"}`))
		assert.True(errors.Is(err, ErrNotFound))
		assert.Nil(reply)
	}
	{
		reply, err := mux.Invoke(ctx, []byte(`{"bar":"baz"}`))
		assert.True(errors.Is(err, ErrNotFound))
		assert.Nil(reply)
	}
}
