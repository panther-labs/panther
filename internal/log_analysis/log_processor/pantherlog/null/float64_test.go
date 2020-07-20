package null

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
	"encoding/json"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestFloat64Codec(t *testing.T) {
	type A struct {
		Foo Float64 `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"42.42"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromFloat64(42.42), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42.42}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":42.42}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromFloat64(42.42), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42.42}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":""}`, &a)
		require.NoError(t, err)
		require.Equal(t, Float64{}, a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":null}`, &a)
		require.NoError(t, err)
		require.Equal(t, Float64{}, a.Foo)
		require.False(t, a.Foo.Exists)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		s := FromFloat64(42.42)
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `42.42`, data)
	}
	{
		s := Float64{}
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `null`, data)
	}
}
func TestFloat64UnmarshalJSON(t *testing.T) {
	type A struct {
		Foo Float64 `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"42.42"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromFloat64(42.42), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42.42}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":42.42}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromFloat64(42.42), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42.42}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":""}`), &a)
		require.NoError(t, err)
		require.Equal(t, Float64{}, a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":null}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":null}`), &a)
		require.NoError(t, err)
		require.Equal(t, Float64{}, a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":null}`, string(data))
	}
	{
		s := FromFloat64(42.42)
		data, err := json.Marshal(&s)
		require.NoError(t, err)
		require.Equal(t, `42.42`, string(data))
	}
	{
		s := Float64{}
		data, err := json.Marshal(&s)
		require.NoError(t, err)
		require.Equal(t, `null`, string(data))
	}
}

func TestFloat64IsNull(t *testing.T) {
	n := Float64{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Float64{
		Value:  42.42,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Float64{}
	require.True(t, n.IsNull())
	n = Float64{
		Value: 12.01,
	}
	require.True(t, n.IsNull())
}
