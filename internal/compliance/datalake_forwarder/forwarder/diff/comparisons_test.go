package diff

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompJsonsSimple(t *testing.T) {
	// Test a very simple no diffs
	left := `{"fieldA": 42, "fieldB": "hello, world!"}`
	right := `{"fieldB": "hello, world!", "fieldA": 42}`
	diffs, err := CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	assert.Nil(t, diffs)

	// Test a very simple diff
	left = `{"fieldA": 42, "fieldB": "Hello, World!"}`
	right = `{"fieldA": 72, "fieldB": "hello, world!"}`
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff := map[string]Diff{
		"fieldA": {
			From: 42,
			To:   72,
		},
		"fieldB": {
			From: "Hello, World!",
			To:   "hello, world!",
		},
	}
	assert.Equal(t, expectedDiff, diffs)

	// Test a partial diff
	left = `{"fieldA": 42, "fieldB": "Hello, World!", "fieldC": 42.0}`
	right = `{"fieldA": 42, "fieldB": "Hello, World!", "fieldC": 42.1}`
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff = map[string]Diff{
		"fieldC": {
			From: 42.0,
			To:   42.1,
		},
	}
	assert.Equal(t, expectedDiff, diffs)
}

func TestCompJsonsObjects(t *testing.T) {
	// Test nested objects are equal
	left := `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"nestedFieldTwo": {"id": "abc123", "count": 72}, "otherNestedFieldTwo": 83.0}}}`
	right := `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"otherNestedFieldTwo": 83.0, "nestedFieldTwo": {"id": "abc123", "count": 72}}}}`
	diffs, err := CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	assert.Nil(t, diffs)

	// Test deeply nested objects are not equal
	left = `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"nestedFieldTwo": {"id": "abc123", "count": 72, "nestedFieldThree": {"ImDifferent": "hello"}}, "otherNestedFieldTwo": 83.0}}}`    // nolint:lll
	right = `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"otherNestedFieldTwo": 83.0, "nestedFieldTwo": {"id": "abc123", "count": 75, "nestedFieldThree": {"ImDifferent": "goodbye"}}}}}` // nolint:lll
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff := map[string]Diff{
		"fieldB.nestedFieldOne.nestedFieldTwo.nestedFieldThree.ImDifferent": {
			From: "hello",
			To:   "goodbye",
		},
		"fieldB.nestedFieldOne.nestedFieldTwo.count": {
			From: 72,
			To:   75,
		},
	}
	assert.Equal(t, expectedDiff, diffs)

	// Test right missing key
	left = `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"nestedFieldTwo": {"id": "abc123", "count": 72}, "otherNestedFieldTwo": 83.0}}}`
	right = `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"otherNestedFieldTwo": 83.0, "nestedFieldTwo": {"id": "abc123"}}}}`
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff = map[string]Diff{
		"fieldB.nestedFieldOne.nestedFieldTwo.count": {
			From: 72,
			To:   nil,
		},
	}
	assert.Equal(t, expectedDiff, diffs)

	// Test left missing key
	left = `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"nestedFieldTwo": {"count": 72, "id": "abc123"}}}}`
	right = `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"otherNestedFieldTwo": 83.5, "nestedFieldTwo": {"count": 72, "id": "abc123"}}}}`
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff = map[string]Diff{
		"fieldB.nestedFieldOne.otherNestedFieldTwo": {
			From: nil,
			To:   83.5,
		},
	}
	assert.Equal(t, expectedDiff, diffs)
}

func TestCompJsonsArrays(t *testing.T) {
	// Test simple arrays are equal
	left := `{"fieldA": 42, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "count"], "fieldB": 83.0}}}`
	right := `{"fieldA": 42, "fieldB": 83.0, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "count"]}}}`
	diffs, err := CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	assert.Nil(t, diffs)

	// Test simple arrays are not equal
	left = `{"fieldA": 42, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "counted"], "fieldB": 83.0}}}`
	right = `{"fieldA": 42, "fieldB": 83.0, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "count"]}}}`
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff := map[string]Diff{
		"fieldC.2": {
			From: "counted",
			To:   "count",
		},
	}
	assert.Equal(t, expectedDiff, diffs)

	// Test left array is longer
	left = `{"fieldA": 42, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "count", "extra value"], "fieldB": 83.0}}}`
	right = `{"fieldA": 42, "fieldB": 83.0, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "count"]}}}`
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff = map[string]Diff{
		"fieldC.3": {
			From: "extra value",
			To:   nil,
		},
	}
	assert.Equal(t, expectedDiff, diffs)

	// Test right array is longer
	left = `{"fieldA": 42, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "count", "extra value"], "fieldB": 83.0}}}`
	right = `{"fieldA": 42, "fieldB": 83.0, "fieldC": ["nestedFieldOne", "nestedFieldTwo", "count", "extra value", "yet another value"]}}}`
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff = map[string]Diff{
		"fieldC.4": {
			From: nil,
			To:   "yet another value",
		},
	}
	assert.Equal(t, expectedDiff, diffs)
}

func TestCompJsonsComplex(t *testing.T) {
	// Test deeply nested objects are equal with arrays & objects
	left := `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"nestedFieldTwo": [{"id": "abc123"}, {"count": 72}, {"nestedFieldThree": {"ImDifferent": "hello"}}], "otherNestedFieldTwo": 83.0}}}`  // nolint:lll
	right := `{"fieldA": 42, "fieldB": {"nestedFieldOne": {"otherNestedFieldTwo": 83.0, "nestedFieldTwo": [{"id": "abc123"}, {"count": 72}, {"nestedFieldThree": {"ImDifferent": "hello"}}]}}}` // nolint:lll
	diffs, err := CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	assert.Nil(t, diffs)

	// Ok lets get a little crazy...
	// (I recommend https://jsoneditoronline.org/ for help constructing/editing these tests)
	left = `{"fieldA":[1,2,3],"fieldB":true,"fieldC":"gold","fieldD":null,"fieldE":123,"fieldF":{"a":"b","c":"d"},"fieldG":"Hello World","fieldH":{"a":52,"b":41,"c":null},"fieldI":{"a":{"b":["thing1","thing2","thing3",{"a":111,"b":222,"c":["yes","no"]}]},"b":"thing","c":null},"fieldJ":[{"ip":"0.0.0.0","action":"allow","port":1024,"egress":true},{"ip":"0.0.0.0","action":"allow","port":1024,"egress":false},{"ip":"1.1.1.1","action":"deny","port":22,"egress":false}]}`  // nolint:lll
	right = `{"fieldA":[1,2,3],"fieldI":{"a":{"b":["thing1","thing2","thing3",{"b":222,"a":111,"c":["yes","no"]}]},"b":"thing","c":null},"fieldB":true,"fieldE":123,"fieldF":{"c":"d","a":"b"},"fieldG":"Hello World","fieldH":{"a":52,"b":41,"c":null},"fieldJ":[{"ip":"0.0.0.0","action":"allow","port":1024,"egress":true},{"ip":"0.0.0.0","action":"allow","port":1024,"egress":false},{"ip":"1.1.1.1","action":"deny","port":22,"egress":false}],"fieldC":"gold","fieldD":null}` // nolint:lll
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	assert.Nil(t, diffs)

	left = `{"fieldA":[1,2,3],"fieldB":true,"fieldC":"gold","fieldD":null,"fieldE":123,"fieldF":{"a":"b","c":"d"},"fieldG":"Hello World","fieldH":{"a":52,"b":41,"c":null},"fieldI":{"a":{"b":["thing1","thing2","thing3",{"a":111,"b":222,"c":["yes","no"]}]},"b":"thing","c":null},"fieldJ":[{"ip":"0.0.0.0","action":"allow","port":1024,"egress":true},{"ip":"0.0.0.0","action":"allow","port":1024,"egress":false},{"ip":"1.1.1.1","action":"deny","port":22,"egress":false}]}`        // nolint:lll
	right = `{"fieldA":[1,2],"fieldI":{"a":{"b":["thing1","thing2","thing3",{"b":222,"a":11111,"c":["yes","no","maybe so"]}]},"b":"thing","c":true},"fieldB":true,"fieldE":123,"fieldF":{"c":"d","a":"b"},"fieldG":"Hello World","fieldH":{"a":52,"c":null},"fieldJ":[{"ip":"0.0.0.0","action":"allow","port":1024,"egress":true},{"ip":"0.0.0.0","action":"allow","port":1024,"egress":false},{"ip":"1.1.1.1","action":"allow","port":22,"egress":false}],"fieldC":null,"fieldD":"green"}` // nolint:lll
	diffs, err = CompJsons([]byte(left), []byte(right))
	require.NoError(t, err)
	expectedDiff := map[string]Diff{
		"fieldA.2":         {From: 3, To: nil},
		"fieldC":           {From: "gold", To: nil},
		"fieldD":           {From: nil, To: "green"},
		"fieldH.b":         {From: 41, To: nil},
		"fieldI.a.b.3.a":   {From: 111, To: 11111},
		"fieldI.a.b.3.c.2": {From: nil, To: "maybe so"},
		"fieldI.c":         {From: nil, To: true},
		"fieldJ.2.action":  {From: "deny", To: "allow"},
	}
	assert.Equal(t, expectedDiff, diffs)
}
