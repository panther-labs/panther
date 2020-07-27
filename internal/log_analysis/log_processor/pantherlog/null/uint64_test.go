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

func TestUint64Codec(t *testing.T) {
	type A struct {
		Foo Uint64 `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typUint64, []unmarshalTest{
		{"", `"42"`, Uint64{Value: 42, Exists: true}, false},
		{"", `"-42"`, Uint64{}, true},
		{"", `""`, Uint64{}, false},
		{"", `null`, Uint64{}, false},
		{"number positive", `42`, Uint64{Value: 42, Exists: true}, false},
		{"number negative", `-42`, Uint64{}, true},
		{"", `"abc"`, Uint64{}, true},
		{"", `[]`, Uint64{}, true},
		{"", `{}`, Uint64{}, true},
		{"", `{"foo":"42"}`, A{Foo: Uint64{Value: 42, Exists: true}}, false},
		{"", `{"foo":""}`, A{}, false},
		{"", `{"foo":null}`, A{}, false},
		{"", `{"foo":"abc"}`, A{}, true},
		{"", `{"foo":[]}`, A{}, true},
		{"", `{"foo":{}}`, A{}, true},
		{"", `{"foo":42}`, A{Foo: Uint64{Value: 42, Exists: true}}, false},
		{"", `{"foo":-42}`, A{}, true},
	})
	runTestsMarshal(t, typUint64, []marshalTest{
		{"", Uint64{Value: 42, Exists: true}, `42`, `42`},
		{"", Uint64{Value: 0, Exists: true}, `0`, `0`},
		{"", Uint64{}, `null`, `null`},
		{"", A{Foo: Uint64{Value: 42, Exists: true}}, `{"foo":42}`, `{"foo":42}`},
		{"", A{}, `{}`, `{"foo":null}`},
		{"", A{Foo: Uint64{Value: 0, Exists: true}}, `{"foo":0}`, `{"foo":0}`},
	})
}

func TestUint64IsNull(t *testing.T) {
	n := Uint64{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Uint64{
		Value:  42,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Uint64{}
	require.True(t, n.IsNull())
	n = Uint64{
		Value: 12,
	}
	require.True(t, n.IsNull())
}
