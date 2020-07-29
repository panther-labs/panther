package anystring

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

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestAnyStringMarshal(t *testing.T) {
	var any Set

	// nil case
	expectedJSON := `[]`
	actualJSON, err := jsoniter.Marshal(&any)
	require.NoError(t, err)
	require.Equal(t, expectedJSON, string(actualJSON))

	// non-nil case
	any.Values = []string{"a", "c", "b"}
	expectedJSON = `["a","b","c"]` // should be sorted
	actualJSON, err = jsoniter.Marshal(&any)
	require.NoError(t, err)
	require.Equal(t, expectedJSON, string(actualJSON))
}

func TestAnyStringUnmarshal(t *testing.T) {
	var any Set

	// nil case
	jsonString := `[]`
	expectedAny := Set{
		Values: []string{},
	}
	err := jsoniter.Unmarshal(([]byte)(jsonString), &any)
	require.NoError(t, err)
	require.Equal(t, expectedAny, any)

	// non-nil case
	jsonString = `["a"]`
	expectedAny = Set{
		Values: []string{"a"},
	}
	err = jsoniter.Unmarshal(([]byte)(jsonString), &any)
	require.NoError(t, err)
	require.Equal(t, expectedAny, any)
}

func TestAppendAnyString(t *testing.T) {
	value := "a"
	expectedAny := &Set{
		Values: []string{value},
	}
	any := New()
	Append(any, value)
	require.Equal(t, expectedAny, any)
}

func TestAppendAnyStringWithEmptyString(t *testing.T) {
	value := ""           // should not be stored
	expectedAny := &Set{} // empty map
	any := New()
	Append(any, value)
	require.Equal(t, expectedAny, any)
}
