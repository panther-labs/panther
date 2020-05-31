package jsonlob

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestObjectMarshalJSON(t *testing.T) {
	nullJSONString := string(nullJSON)

	// empty test
	obj := NewObject("")
	jsonBytes, err := obj.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, nullJSONString, (string)(jsonBytes))

	// nil test
	obj = nil
	jsonBytes, err = obj.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, nullJSONString, (string)(jsonBytes))

	// sth test
	nonNullJSONString := `{"foo":"bar", "baz":1}`
	obj = NewObject(nonNullJSONString)
	jsonBytes, err = obj.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, nonNullJSONString, (string)(jsonBytes))
}

func TestObjectUnmarshalJSON(t *testing.T) {
	obj := NewObject("")

	// null test
	err := obj.UnmarshalJSON(nullJSON)
	require.NoError(t, err)
	assert.JSONEq(t, string(*obj), string(nullJSON))

	// empty test
	err = obj.UnmarshalJSON([]byte{})
	require.NoError(t, err)
	assert.Len(t, string(*obj), 0)

	// sth test
	jsonString := `{"foo":"bar", "baz":1}`
	err = obj.UnmarshalJSON([]byte(jsonString))
	require.NoError(t, err)
	assert.JSONEq(t, jsonString, string(*obj))
}
