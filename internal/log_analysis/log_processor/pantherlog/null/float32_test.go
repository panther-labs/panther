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

func TestFloat32Codec(t *testing.T) {
	type A struct {
		Foo Float32 `json:"foo,omitempty"`
	}
	runTestsUnmarshal(t, typFloat32, []unmarshalTest{
		{"", `"4.2"`, Float32{Value: 4.2, Exists: true}, false},
		{"", `"-4.2"`, Float32{Value: -4.2, Exists: true}, false},
		{"", `""`, Float32{}, false},
		{"", `null`, Float32{}, false},
		{"", `4.2`, Float32{Value: 4.2, Exists: true}, false},
		{"", `-4.2`, Float32{Value: -4.2, Exists: true}, false},
		{"", `"abc"`, Float32{}, true},
		{"", `[]`, Float32{}, true},
		{"", `{}`, Float32{}, true},
		{"", `{"foo":"4.2"}`, A{Foo: Float32{Value: 4.2, Exists: true}}, false},
		{"", `{"foo":""}`, A{}, false},
		{"", `{"foo":null}`, A{}, false},
		{"", `{"foo":"abc"}`, A{}, true},
		{"", `{"foo":[]}`, A{}, true},
		{"", `{"foo":{}}`, A{}, true},
		{"", `{"foo":4.2}`, A{Foo: Float32{Value: 4.2, Exists: true}}, false},
		{"", `{"foo":-4.2}`, A{Foo: Float32{Value: -4.2, Exists: true}}, false},
	})
	runTestsMarshal(t, typFloat32, []marshalTest{
		{"", Float32{Value: 4.2, Exists: true}, `4.2`, `4.2`},
		{"", Float32{Value: -4.2, Exists: true}, `-4.2`, `-4.2`},
		{"", Float32{Value: 0, Exists: true}, `0`, `0`},
		{"", Float32{}, `null`, `null`},
		{"", A{Foo: Float32{Value: 4.2, Exists: true}}, `{"foo":4.2}`, `{"foo":4.2}`},
		{"", A{Foo: Float32{Value: -4.2, Exists: true}}, `{"foo":-4.2}`, `{"foo":-4.2}`},
		{"", A{Foo: Float32{Value: 0, Exists: true}}, `{"foo":0}`, `{"foo":0}`},
		{"", A{Foo: Float32{}}, `{}`, `{"foo":null}`},
	})
}

func TestFloat32IsNull(t *testing.T) {
	n := Float32{
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Float32{
		Value:  42.42,
		Exists: true,
	}
	require.False(t, n.IsNull())
	n = Float32{}
	require.True(t, n.IsNull())
	n = Float32{
		Value: 12.01,
	}
	require.True(t, n.IsNull())
}
