package parsers

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
	"strconv"
	"strings"
)

func CsvStringToPointer(value string) *string {
	if value == "-" {
		return nil
	}
	return &value
}

func CsvStringToIntPointer(value string) *int {
	if value == "-" {
		return nil
	}
	result, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return &result
}

func CsvStringToInt16Pointer(value string) *int16 {
	if value == "-" {
		return nil
	}
	result, err := strconv.ParseInt(value, 10, 16)
	if err != nil {
		return nil
	}
	returnValue := int16(result)
	return &returnValue
}

func CsvStringToFloat64Pointer(value string) *float64 {
	if value == "-" {
		return nil
	}
	result, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil
	}
	return &result
}

func CsvStringToArray(value string) []string {
	if value == "-" {
		return []string{}
	}

	return strings.Split(value, ",")
}
