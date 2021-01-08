package utils

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

import "reflect"

// ParseTagSlice takes a list of structs representing tags, and returns a map of key/value pairs
func ParseTagSlice(slice interface{}) map[string]*string {
	typedSlice := reflect.ValueOf(slice)

	tags := make(map[string]*string, typedSlice.Len())
	for i := 0; i < typedSlice.Len(); i++ {
		tagStruct := reflect.Indirect(typedSlice.Index(i))
		key := tagStruct.FieldByName("Key")
		value := tagStruct.FieldByName("Value")

		if !key.IsValid() || !value.IsValid() {
			return nil
		}
		tags[*key.Interface().(*string)] = value.Interface().(*string)
	}

	return tags
}
