// nolint: dupl
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

func TestBooleanCodec(t *testing.T) {
	type A struct {
		Foo Boolean `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"0"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"FALSE"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"F"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"false"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"t"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"1"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"TRUE"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"T"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"true"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"t"}`, &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":42}`, &a)
		require.Error(t, err)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":""}`, &a)
		require.NoError(t, err)
		require.Equal(t, Boolean{}, a.Foo)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":null}`, &a)
		require.NoError(t, err)
		require.Equal(t, Boolean{}, a.Foo)
		require.False(t, a.Foo.Exists)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		s := FromBoolean(true)
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `true`, data)
	}
	{
		s := Boolean{}
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `null`, data)
	}
}
func TestBooleanUnmarshalJSON(t *testing.T) {
	type A struct {
		Foo Boolean `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"0"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"FALSE"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"F"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"false"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(false), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":false}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"t"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"1"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"TRUE"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"T"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"true"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"t"}`), &a)
		require.NoError(t, err)
		require.Equal(t, FromBoolean(true), a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":true}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"42"}`), &a)
		require.Error(t, err)
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":42}`), &a)
		require.Error(t, err)
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":""}`), &a)
		require.NoError(t, err)
		require.Equal(t, Boolean{}, a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":null}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":null}`), &a)
		require.NoError(t, err)
		require.Equal(t, Boolean{}, a.Foo)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":null}`, string(data))
	}
	{
		s := FromBoolean(true)
		data, err := json.Marshal(&s)
		require.NoError(t, err)
		require.Equal(t, `true`, string(data))
	}
	{
		s := Boolean{}
		data, err := json.Marshal(&s)
		require.NoError(t, err)
		require.Equal(t, `null`, string(data))
	}
}

func TestBooleanIsNull(t *testing.T) {
	n := Boolean{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Boolean{
		Value:  true,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Boolean{}
	require.True(t, n.IsNull())
	n = Boolean{
		Value: true,
	}
	require.True(t, n.IsNull())
}
