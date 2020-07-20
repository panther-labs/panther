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

func TestInt16Codec(t *testing.T) {
	type A struct {
		Foo Int16 `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"42"}`, &a)
		require.NoError(t, err)
		require.Equal(t, int16(42), a.Foo.Value)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":42}`, &a)
		require.NoError(t, err)
		require.Equal(t, int16(42), a.Foo.Value)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":""}`, &a)
		require.NoError(t, err)
		require.Equal(t, Int16{}, a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":null}`, &a)
		require.NoError(t, err)
		require.Equal(t, Int16{}, a.Foo)
		require.False(t, a.Foo.Exists)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		s := FromInt16(42)
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `42`, data)
	}
	{
		s := Int16{}
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `null`, data)
	}
}
func TestInt16UnmarshalJSON(t *testing.T) {
	type A struct {
		Foo Int16 `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"42"}`), &a)
		require.NoError(t, err)
		require.True(t, a.Foo.Exists)
		require.Equal(t, int16(42), a.Foo.Value)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":42}`), &a)
		require.NoError(t, err)
		require.True(t, a.Foo.Exists)
		require.Equal(t, int16(42), a.Foo.Value)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":42}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":""}`), &a)
		require.NoError(t, err)
		require.Equal(t, Int16{}, a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":null}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":null}`), &a)
		require.NoError(t, err)
		require.Equal(t, Int16{}, a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":null}`, string(data))
	}
	{
		s := FromInt16(42)
		data, err := json.Marshal(&s)
		require.NoError(t, err)
		require.Equal(t, `42`, string(data))
	}
	{
		s := Int16{}
		data, err := json.Marshal(&s)
		require.NoError(t, err)
		require.Equal(t, `null`, string(data))
	}
}

func TestInt16IsNull(t *testing.T) {
	n := Int16{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Int16{
		Value:  42,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Int16{}
	require.True(t, n.IsNull())
	n = Int16{
		Value: 12,
	}
	require.True(t, n.IsNull())
}
