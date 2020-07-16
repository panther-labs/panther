package pantherlog

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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"reflect"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/null"
)

func TestNewEnumDecoder(t *testing.T) {
	type FooEnum null.String
	typFooEnum := reflect.TypeOf(FooEnum{})

	// Check error cases
	{
		enum := Enum{}
		decoder, err := NewEnumDecoder(typFooEnum, enum)
		require.Error(t, err)
		require.Nil(t, decoder)
	}
	{
		enum := Enum{
			1: "Foo",
			2: "Foo",
		}
		decoder, err := NewEnumDecoder(typFooEnum, enum)
		require.Error(t, err)
		require.Nil(t, decoder)
	}
	{
		enum := Enum{
			1: "Foo",
		}
		decoder, err := NewEnumDecoder(nil, enum)
		require.Error(t, err)
		require.Nil(t, decoder)
	}
	{
		enum := Enum{
			1: "Foo",
		}
		decoder, err := NewEnumDecoder(reflect.TypeOf(""), enum)
		require.Error(t, err)
		require.Nil(t, decoder)
	}
	enum := Enum{
		1: "Foo",
		2: "Bar",
		3: "Baz",
	}

	decoder, err := NewEnumDecoder(typFooEnum, enum)
	require.NoError(t, err)
	jsoniter.RegisterTypeDecoder(typFooEnum.String(), decoder)
	jsoniter.RegisterTypeEncoder(typFooEnum.String(), null.StringEncoder())
	type A struct {
		Foo FooEnum `json:"foo,omitempty"`
	}
	{
		a := A{}
		input := `{"foo": 2 }`
		require.NoError(t, jsoniter.UnmarshalFromString(input, &a))
		require.Equal(t, FooEnum(null.FromString("Bar")), a.Foo)
		actual, err := jsoniter.MarshalToString(a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"Bar"}`, actual)
	}
	{
		a := A{}
		input := `{"foo": "" }`
		require.NoError(t, jsoniter.UnmarshalFromString(input, &a))
		require.Equal(t, FooEnum{}, a.Foo)
		actual, err := jsoniter.MarshalToString(a)
		require.NoError(t, err)
		require.Equal(t, `{}`, actual)
	}
	{
		a := A{}
		input := `{}`
		require.NoError(t, jsoniter.UnmarshalFromString(input, &a))
		require.Equal(t, FooEnum{}, a.Foo)
		actual, err := jsoniter.MarshalToString(a)
		require.NoError(t, err)
		require.Equal(t, `{}`, actual)
	}
	{
		a := A{}
		input := `{"foo": null}`
		require.NoError(t, jsoniter.UnmarshalFromString(input, &a))
		require.Equal(t, FooEnum{}, a.Foo)
		actual, err := jsoniter.MarshalToString(a)
		require.NoError(t, err)
		require.Equal(t, `{}`, actual)
	}
	{
		a := A{}
		input := `{"foo": "2" }`
		require.NoError(t, jsoniter.UnmarshalFromString(input, &a))
		require.Equal(t, FooEnum(null.FromString("Bar")), a.Foo)
		actual, err := jsoniter.MarshalToString(a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"Bar"}`, actual)
	}
	{
		a := A{}
		input := `{"foo": "42" }`
		require.NoError(t, jsoniter.UnmarshalFromString(input, &a))
		require.Equal(t, FooEnum(null.FromString("42")), a.Foo)
		actual, err := jsoniter.MarshalToString(a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"42"}`, actual)
	}
	{
		a := A{}
		input := `{"foo": 42 }`
		require.NoError(t, jsoniter.UnmarshalFromString(input, &a))
		require.Equal(t, FooEnum(null.FromString("42")), a.Foo)
		actual, err := jsoniter.MarshalToString(a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"42"}`, actual)
	}
}
