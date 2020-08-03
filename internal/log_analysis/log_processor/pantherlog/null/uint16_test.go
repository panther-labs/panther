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

func TestUint16Codec(t *testing.T) {
	type A struct {
		Foo Uint16 `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typUint16, []unmarshalTest{
		{"", `"42"`, Uint16{Value: 42, Exists: true}, false},
		{"", `"-42"`, Uint16{}, true},
		{"", `""`, Uint16{}, false},
		{"", `null`, Uint16{}, false},
		{"number positive", `42`, Uint16{Value: 42, Exists: true}, false},
		{"number negative", `-42`, Uint16{}, true},
		{"", `"abc"`, Uint16{}, true},
		{"", `[]`, Uint16{}, true},
		{"", `{}`, Uint16{}, true},
		{"", `{"foo":"42"}`, A{Foo: Uint16{Value: 42, Exists: true}}, false},
		{"", `{"foo":""}`, A{}, false},
		{"", `{"foo":null}`, A{}, false},
		{"", `{"foo":"abc"}`, A{}, true},
		{"", `{"foo":[]}`, A{}, true},
		{"", `{"foo":{}}`, A{}, true},
		{"", `{"foo":42}`, A{Foo: Uint16{Value: 42, Exists: true}}, false},
		{"", `{"foo":-42}`, A{}, true},
	})
	runTestsMarshal(t, typUint16, []marshalTest{
		{"", Uint16{Value: 42, Exists: true}, `42`, `42`},
		{"", Uint16{Value: 0, Exists: true}, `0`, `0`},
		{"", Uint16{}, `null`, `null`},
		{"", A{Foo: Uint16{Value: 42, Exists: true}}, `{"foo":42}`, `{"foo":42}`},
		{"", A{}, `{}`, `{"foo":null}`},
		{"", A{Foo: Uint16{Value: 0, Exists: true}}, `{"foo":0}`, `{"foo":0}`},
	})
}

func TestUint16IsNull(t *testing.T) {
	n := Uint16{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Uint16{
		Value:  42,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Uint16{}
	require.True(t, n.IsNull())
	n = Uint16{
		Value: 12,
	}
	require.True(t, n.IsNull())
}
