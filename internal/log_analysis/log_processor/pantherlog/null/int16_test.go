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

func TestInt16Codec(t *testing.T) {
	type A struct {
		Foo Int16 `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typInt16, []unmarshalTest{
		{"", `"42"`, Int16{Value: 42, Exists: true}, false},
		{"", `"-42"`, Int16{Value: -42, Exists: true}, false},
		{"", `""`, Int16{}, false},
		{"", `null`, Int16{}, false},
		{"", `42`, Int16{Value: 42, Exists: true}, false},
		{"", `-42`, Int16{Value: -42, Exists: true}, false},
		{"", `"abc"`, Int16{}, true},
		{"", `[]`, Int16{}, true},
		{"", `{}`, Int16{}, true},
		{"", `{"foo":"42"}`, A{Foo: Int16{Value: 42, Exists: true}}, false},
		{"", `{"foo":""}`, A{}, false},
		{"", `{"foo":null}`, A{}, false},
		{"", `{"foo":"abc"}`, A{}, true},
		{"", `{"foo":[]}`, A{}, true},
		{"", `{"foo":{}}`, A{}, true},
		{"", `{"foo":42}`, A{Foo: Int16{Value: 42, Exists: true}}, false},
		{"", `{"foo":-42}`, A{Foo: Int16{Value: -42, Exists: true}}, false},
	})
	runTestsMarshal(t, typInt16, []marshalTest{
		{"", Int16{Value: 42, Exists: true}, `42`, `42`},
		{"", Int16{Value: -42, Exists: true}, `-42`, `-42`},
		{"", Int16{Value: 0, Exists: true}, `0`, `0`},
		{"", Int16{}, `null`, `null`},
		{"", A{Foo: Int16{Value: 42, Exists: true}}, `{"foo":42}`, `{"foo":42}`},
		{"", A{Foo: Int16{Value: -42, Exists: true}}, `{"foo":-42}`, `{"foo":-42}`},
		{"", A{Foo: Int16{Value: 0, Exists: true}}, `{"foo":0}`, `{"foo":0}`},
		{"", A{Foo: Int16{}}, `{}`, `{"foo":null}`},
	})
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
