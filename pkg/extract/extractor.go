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
	jsoniter "github.com/json-iterator/go"
	"github.com/tidwall/gjson"
)

type Extractor interface {
	Extract(key, value gjson.Result)
}

// Extract parses RAW JSON extracting tasty things by calling Parsed()
func Extract(rawMessage *jsoniter.RawMessage, extractors ...Extractor) {
	if rawMessage == nil {
		return
	}
	result := gjson.ParseBytes(*rawMessage)
	Parsed(result, extractors...)
}

// Parsed walks parsed JSON extracting tasty things (use if you already parsed the JSON)
func Parsed(result gjson.Result, extractors ...Extractor) {
	result.ForEach(func(key, value gjson.Result) bool {
		for _, extractor := range extractors {
			extractor.Extract(key, value)
		}
		if value.IsArray() || value.IsObject() {
			Parsed(value, extractors...)
		}
		return true // keep iterating
	})
}
