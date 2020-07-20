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

func TestInt64Codec(t *testing.T) {
	type A struct {
		Foo Int64 `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typInt64, []unmarshalTest{
		{"", `"42"`, Int64{Value: 42, Exists: true}, false},
		{"", `"-42"`, Int64{Value: -42, Exists: true}, false},
		{"", `""`, Int64{}, false},
		{"", `null`, Int64{}, false},
		{"", `42`, Int64{Value: 42, Exists: true}, false},
		{"", `-42`, Int64{Value: -42, Exists: true}, false},
		{"", `"abc"`, Int64{}, true},
		{"", `[]`, Int64{}, true},
		{"", `{}`, Int64{}, true},
		{"", `{"foo":"42"}`, A{Foo: Int64{Value: 42, Exists: true}}, false},
		{"", `{"foo":""}`, A{}, false},
		{"", `{"foo":null}`, A{}, false},
		{"", `{"foo":"abc"}`, A{}, true},
		{"", `{"foo":[]}`, A{}, true},
		{"", `{"foo":{}}`, A{}, true},
		{"", `{"foo":42}`, A{Foo: Int64{Value: 42, Exists: true}}, false},
		{"", `{"foo":-42}`, A{Foo: Int64{Value: -42, Exists: true}}, false},
	})
	runTestsMarshal(t, typInt64, []marshalTest{
		{"", Int64{Value: 42, Exists: true}, `42`, `42`},
		{"", Int64{Value: -42, Exists: true}, `-42`, `-42`},
		{"", Int64{Value: 0, Exists: true}, `0`, `0`},
		{"", Int64{}, `null`, `null`},
		{"", A{Foo: Int64{Value: 42, Exists: true}}, `{"foo":42}`, `{"foo":42}`},
		{"", A{Foo: Int64{Value: -42, Exists: true}}, `{"foo":-42}`, `{"foo":-42}`},
		{"", A{Foo: Int64{Value: 0, Exists: true}}, `{"foo":0}`, `{"foo":0}`},
		{"", A{Foo: Int64{}}, `{}`, `{"foo":null}`},
	})
}

func TestInt64IsNull(t *testing.T) {
	n := Int64{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Int64{
		Value:  42,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Int64{}
	require.True(t, n.IsNull())
	n = Int64{
		Value: 12,
	}
	require.True(t, n.IsNull())
}
