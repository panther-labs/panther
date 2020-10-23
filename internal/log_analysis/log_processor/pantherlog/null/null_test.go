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
	"reflect"
	"strconv"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-playground/validator.v9"
)

func TestRegisterValidators(t *testing.T) {
	v := validator.New()
	type T struct {
		RequiredStringFoo String `validate:"omitempty,eq=foo"`
		RequiredString    String `validate:"required"`
		RequiredInt64     Int64  `validate:"required"`
	}
	RegisterValidators(v)
	assert.NoError(t, v.Struct(T{
		RequiredString: FromString(""),
		RequiredInt64:  FromInt64(0),
	}))
	require.Error(t, v.Struct(T{}))
	require.Error(t, v.Struct(T{
		RequiredStringFoo: FromString("bar"),
		RequiredInt64:     FromInt64(42),
	}))
	require.Error(t, v.Struct(T{
		RequiredStringFoo: FromString("foo"),
		RequiredInt64:     FromInt64(0),
	}))
	require.NoError(t, v.Struct(T{
		RequiredStringFoo: FromString("foo"),
		RequiredString:    FromString(""),
		RequiredInt64:     FromInt64(42),
	}))
}

type unmarshalTest struct {
	Name    string
	Input   string
	Expect  interface{}
	WantErr bool
}

func runTestsUnmarshal(t *testing.T, typ reflect.Type, testCases []unmarshalTest) {
	t.Helper()
	prefix := typ.String() + "_"
	for i, tc := range testCases {
		tc := tc
		name := tc.Name
		if name == "" {
			name = strconv.Itoa(i)
		}
		name = prefix + name
		t.Run(name+"_jsoniter_unmarshal", func(t *testing.T) {
			val := reflect.New(reflect.TypeOf(tc.Expect))
			v := val.Interface()
			err := jsoniter.UnmarshalFromString(tc.Input, v)
			if tc.WantErr {
				require.Error(t, err, "Expecting decode error")
				return
			}
			require.NoError(t, err, "Unexpected error")
			require.Equal(t, tc.Expect, val.Elem().Interface())
		})
		t.Run(name+"_json_unmarshal", func(t *testing.T) {
			val := reflect.New(reflect.TypeOf(tc.Expect))
			v := val.Interface()
			err := json.Unmarshal([]byte(tc.Input), v)
			if tc.WantErr {
				require.Error(t, err, "Expecting decode error")
				return
			}
			require.NoError(t, err, "Unexpected error")
			require.Equal(t, tc.Expect, val.Elem().Interface())
		})
	}
}

type marshalTest struct {
	Name      string
	Input     interface{}
	Expect    string
	ExpectStd string
}

func runTestsMarshal(t *testing.T, typ reflect.Type, testCases []marshalTest) {
	t.Helper()
	prefix := typ.String() + "_"
	for i, tc := range testCases {
		tc := tc
		name := tc.Name
		if name == "" {
			name = strconv.Itoa(i)
		}
		name = prefix + name
		t.Run(name+"_jsoniter_marshal", func(t *testing.T) {
			actual, err := jsoniter.MarshalToString(tc.Input)
			require.NoError(t, err, "Unexpected error")
			require.Equal(t, tc.Expect, actual)
		})
		t.Run(name+"_json_marshal", func(t *testing.T) {
			actual, err := json.Marshal(tc.Input)
			require.NoError(t, err, "Unexpected error")
			require.Equal(t, tc.ExpectStd, string(actual))
		})
	}
}
