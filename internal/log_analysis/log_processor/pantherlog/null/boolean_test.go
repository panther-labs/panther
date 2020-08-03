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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBooleanCodec(t *testing.T) {
	type A struct {
		Foo Bool `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typBoolean, []unmarshalTest{
		{`"true"`, `"true"`, Bool{Value: true, Exists: true}, false},
		{`null`, `null`, Bool{}, false},
		{`""`, `""`, Bool{}, false},
		{`true`, `true`, Bool{Value: true, Exists: true}, false},
		{`1`, `1`, Bool{Value: true, Exists: true}, false},
		{`"TRUE"`, `"TRUE"`, Bool{Value: true, Exists: true}, false},
		{`"t"`, `"t"`, Bool{Value: true, Exists: true}, false},
		{`"T"`, `"T"`, Bool{Value: true, Exists: true}, false},
		{`"1"`, `"1"`, Bool{Value: true, Exists: true}, false},
		{`"false"`, `"false"`, Bool{Value: false, Exists: true}, false},
		{`"FALSE"`, `"FALSE"`, Bool{Value: false, Exists: true}, false},
		{`false`, `false`, Bool{Value: false, Exists: true}, false},
		{`"f"`, `"f"`, Bool{Value: false, Exists: true}, false},
		{`"F"`, `"F"`, Bool{Value: false, Exists: true}, false},
		{`"0"`, `"0"`, Bool{Value: false, Exists: true}, false},
		{`0`, `0`, Bool{Value: false, Exists: true}, false},
		{`"abc"`, `"abc"`, Bool{}, true},
		{`[]`, `[]`, Bool{}, true},
		{`{}`, `{}`, Bool{}, true},
		{`10`, `10`, Bool{}, true},
		{`-1`, `-1`, Bool{}, true},
	})
	runTestsMarshal(t, typBoolean, []marshalTest{
		{"", Bool{Value: true, Exists: true}, `true`, `true`},
		{"", Bool{Value: false, Exists: true}, `false`, `false`},
		{"", Bool{}, `null`, `null`},
		{"", A{}, `{}`, `{"foo":null}`},
		{"", A{Foo: Bool{Value: true, Exists: true}}, `{"foo":true}`, `{"foo":true}`},
		{"", A{Foo: Bool{Value: false, Exists: true}}, `{"foo":false}`, `{"foo":false}`},
	})
}

func TestBooleanIsNull(t *testing.T) {
	n := Bool{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Bool{
		Value:  true,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Bool{}
	require.True(t, n.IsNull())
	n = Bool{
		Value: true,
	}
	require.True(t, n.IsNull())
}
