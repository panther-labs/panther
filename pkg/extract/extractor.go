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
