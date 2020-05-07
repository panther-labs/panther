package jsonutil

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
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
)

// TODO: [parsers] Add more mappings of invalid Athena field name characters here
// NOTE: The mapping should be easy to remember (so no ASCII code etc) and complex enough
// to avoid possible conflicts with other fields.
var athenaStringReplacer = strings.NewReplacer(
	"@", "_at_sign_",
	",", "_comma_",
	"`", "_backtick_",
	"'", "_apostrophe_",
)

func RewriteFieldNameAthena(name string) string {
	return athenaStringReplacer.Replace(name)
}

// ensures the extension is registered only once
var registerAthenaOnce sync.Once

// RegisterAthenaRewrite registers a jsoniter extension to rewrite field names to Athena compatible on encoding only.
func RegisterAthenaRewrite() {
	registerAthenaOnce.Do(func() {
		// Sets mapping of JSON field names to be compatible with Athena on the encoded output
		jsoniter.RegisterExtension(&encoderRewriteStrategyExtension{
			translate: RewriteFieldNameAthena,
		})
	})
}

type encoderRewriteStrategyExtension struct {
	jsoniter.DummyExtension
	translate func(string) string
}

// UpdateStructDescription maps output field names to
func (extension *encoderRewriteStrategyExtension) UpdateStructDescriptor(structDescriptor *jsoniter.StructDescriptor) {
	for _, binding := range structDescriptor.Fields {
		tag, hastag := binding.Field.Tag().Lookup("json")

		// toName := binding.Field.Name()
		if hastag {
			tagParts := strings.Split(tag, ",")
			if tagParts[0] == "-" {
				continue // hidden field
			}
			if name := tagParts[0]; name != "" {
				// field explicitly named, overwrite
				// toName = name
				binding.ToNames = []string{extension.translate(name)}
			}
		}
	}
}
