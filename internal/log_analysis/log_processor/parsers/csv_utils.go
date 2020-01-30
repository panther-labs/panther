package parsers

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	"github.com/aws/aws-sdk-go/aws"
)

func CsvStringToPointer(value string) *string {
	if value == "-" {
		return nil
	}
	return aws.String(value)
}

func CsvStringToIntPointer(value string) *int {
	if value == "-" {
		return nil
	}
	result, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return aws.Int(result)
}

func CsvStringToInt16Pointer(value string) *int16 {
	if value == "-" {
		return nil
	}
	result, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return aws.Int16(int16(result))
}

func CsvStringToFloat64Pointer(value string) *float64 {
	if value == "-" {
		return nil
	}
	result, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil
	}
	return aws.Float64(result)
}

func CsvStringToArray(value string) []string {
	if value == "-" {
		return []string{}
	}

	return strings.Split(value, ",")
}
