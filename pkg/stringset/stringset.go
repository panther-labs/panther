package stringset

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

// New creates a new set of unique string values
func New(values ...string) []string {
	if values == nil {
		return nil
	}
	return Append(make([]string, 0, len(values)), values...)
}

// Dedup de-duplicates a set of values in-place
func Dedup(values []string) []string {
	if values == nil {
		return nil
	}
	return Append(values[:0], values...)
}

// Concat concatenates all parts into a single set of distinct values
func Concat(parts ...[]string) []string {
	// Collect the max required size
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	// Allocate a big enough slice for all values
	union := make([]string, 0, size)
	// Add all parts omitting duplicate values
	for _, part := range parts {
		union = Append(union, part...)
	}
	return union
}

// Append appends src to dst skipping duplicate values
func Append(dst []string, values ...string) []string {
loopValues:
	for _, value := range values {
		for _, duplicate := range dst {
			if duplicate == value {
				continue loopValues
			}
		}
		dst = append(dst, value)
	}
	return dst
}

// Contains checks if a string set contains a value
func Contains(values []string, seek string) bool {
	for _, v := range values {
		if v == seek {
			return true
		}
	}
	return false
}
