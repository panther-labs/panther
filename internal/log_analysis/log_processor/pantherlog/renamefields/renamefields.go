package renamefields

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
	jsoniter "github.com/json-iterator/go"
)

func New(translate func(string) string) jsoniter.Extension {
	return &renameFieldsExtension{
		translate: translate,
	}
}

type renameFieldsExtension struct {
	jsoniter.DummyExtension
	translate func(string) string
}

// UpdateStructDescription implements jsoniter.Extension.
// It rewrites field names using the provided translate function
func (ext *renameFieldsExtension) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		// WARNING: We need to make a copy of ToNames for this to work properly
		toNames := make([]string, 0, len(binding.ToNames))
		for _, name := range binding.ToNames {
			toNames = append(toNames, ext.translate(name))
		}
		binding.ToNames = toNames
	}
}
