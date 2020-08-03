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

func TestInt32Codec(t *testing.T) {
	type A struct {
		Foo Int32 `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typInt32, []unmarshalTest{
		{"", `"42"`, Int32{Value: 42, Exists: true}, false},
		{"", `"-42"`, Int32{Value: -42, Exists: true}, false},
		{"", `""`, Int32{}, false},
		{"", `null`, Int32{}, false},
		{"", `42`, Int32{Value: 42, Exists: true}, false},
		{"", `-42`, Int32{Value: -42, Exists: true}, false},
		{"", `"abc"`, Int32{}, true},
		{"", `[]`, Int32{}, true},
		{"", `{}`, Int32{}, true},
		{"", `{"foo":"42"}`, A{Foo: Int32{Value: 42, Exists: true}}, false},
		{"", `{"foo":""}`, A{}, false},
		{"", `{"foo":null}`, A{}, false},
		{"", `{"foo":"abc"}`, A{}, true},
		{"", `{"foo":[]}`, A{}, true},
		{"", `{"foo":{}}`, A{}, true},
		{"", `{"foo":42}`, A{Foo: Int32{Value: 42, Exists: true}}, false},
		{"", `{"foo":-42}`, A{Foo: Int32{Value: -42, Exists: true}}, false},
	})
	runTestsMarshal(t, typInt32, []marshalTest{
		{"", Int32{Value: 42, Exists: true}, `42`, `42`},
		{"", Int32{Value: -42, Exists: true}, `-42`, `-42`},
		{"", Int32{Value: 0, Exists: true}, `0`, `0`},
		{"", Int32{}, `null`, `null`},
		{"", A{Foo: Int32{Value: 42, Exists: true}}, `{"foo":42}`, `{"foo":42}`},
		{"", A{Foo: Int32{Value: -42, Exists: true}}, `{"foo":-42}`, `{"foo":-42}`},
		{"", A{Foo: Int32{Value: 0, Exists: true}}, `{"foo":0}`, `{"foo":0}`},
		{"", A{Foo: Int32{}}, `{}`, `{"foo":null}`},
	})
}

func TestInt32IsNull(t *testing.T) {
	n := Int32{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Int32{
		Value:  42,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Int32{}
	require.True(t, n.IsNull())
	n = Int32{
		Value: 12,
	}
	require.True(t, n.IsNull())
}
