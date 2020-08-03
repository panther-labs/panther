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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFloat64Codec(t *testing.T) {
	type A struct {
		Foo Float64 `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typFloat64, []unmarshalTest{
		{"", `"42.42"`, Float64{Value: 42.42, Exists: true}, false},
		{"", `"-42.42"`, Float64{Value: -42.42, Exists: true}, false},
		{"", `""`, Float64{}, false},
		{"", `null`, Float64{}, false},
		{"", `42.42`, Float64{Value: 42.42, Exists: true}, false},
		{"", `-42.42`, Float64{Value: -42.42, Exists: true}, false},
		{"", `"abc"`, Float64{}, true},
		{"", `[]`, Float64{}, true},
		{"", `{}`, Float64{}, true},
		{"", `{"foo":"42.42"}`, A{Foo: Float64{Value: 42.42, Exists: true}}, false},
		{"", `{"foo":""}`, A{}, false},
		{"", `{"foo":null}`, A{}, false},
		{"", `{"foo":"abc"}`, A{}, true},
		{"", `{"foo":[]}`, A{}, true},
		{"", `{"foo":{}}`, A{}, true},
		{"", `{"foo":42.42}`, A{Foo: Float64{Value: 42.42, Exists: true}}, false},
		{"", `{"foo":-42.42}`, A{Foo: Float64{Value: -42.42, Exists: true}}, false},
	})
	runTestsMarshal(t, typFloat64, []marshalTest{
		{"", Float64{Value: 42.42, Exists: true}, `42.42`, `42.42`},
		{"", Float64{Value: -42.42, Exists: true}, `-42.42`, `-42.42`},
		{"", Float64{Value: 0, Exists: true}, `0`, `0`},
		{"", Float64{}, `null`, `null`},
		{"", A{Foo: Float64{Value: 42.42, Exists: true}}, `{"foo":42.42}`, `{"foo":42.42}`},
		{"", A{Foo: Float64{Value: -42.42, Exists: true}}, `{"foo":-42.42}`, `{"foo":-42.42}`},
		{"", A{Foo: Float64{Value: 0, Exists: true}}, `{"foo":0}`, `{"foo":0}`},
		{"", A{Foo: Float64{}}, `{}`, `{"foo":null}`},
	})
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
