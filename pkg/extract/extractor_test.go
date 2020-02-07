package extract

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
