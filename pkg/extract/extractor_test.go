package extract

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"github.com/tidwall/gjson"
)

type TestExtractor struct {
	Key1       string
	List1      []int
	ListOfMaps []map[string]string
}

func (e *TestExtractor) Extract(key, value gjson.Result) {
	switch key.Str {
	case "key1":
		e.Key1 = value.Str
	case "list1":
		if value.IsArray() {
			value.ForEach(func(listKey, listValue gjson.Result) bool {
				e.List1 = append(e.List1, int(listValue.Num))
				return true
			})
		}
	case "listOfMaps":
		if value.IsArray() {
			value.ForEach(func(listKey, listValue gjson.Result) bool {
				newMap := make(map[string]string)
				listValue.ForEach(func(mapKey, mapValue gjson.Result) bool {
					newMap[mapKey.Str] = mapValue.Str
					return true
				})
				e.ListOfMaps = append(e.ListOfMaps, newMap)
				return true
			})
		}
	}
}

func TestExtract(t *testing.T) {
	json := (jsoniter.RawMessage)(`
{
"key1": "value1",
"keyToIgnore": "valueToIgnore"",
"list1": [ 1, 2, 3, 4],
"listOfMaps": [
   { "k1": "v1"},
   { "k2": "v2"}
],
"listToIgnore": ["a", "b", "c"]
}
`)

	testExtractor := &TestExtractor{}
	Extract(&json, testExtractor)

	expected := &TestExtractor{
		Key1:  "value1",
		List1: []int{1, 2, 3, 4},
		ListOfMaps: []map[string]string{
			{"k1": "v1"},
			{"k2": "v2"},
		},
	}
	require.Equal(t, expected, testExtractor)
}
