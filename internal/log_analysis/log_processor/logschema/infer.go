package logschema

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
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
)

// InferJSONValueSchema infers the Value Schema for a JSON value.
//
// It will return `nil` if `x` is `nil` or if it is not one of the types
// defined in https://golang.org/pkg/encoding/json/#Unmarshal
func InferJSONValueSchema(x interface{}) *ValueSchema {
	switch v := x.(type) {
	case map[string]interface{}:
		var fields []FieldSchema
		for key, val := range v {
			vs := InferJSONValueSchema(val)
			if vs == nil {
				continue
			}
			fields = append(fields, FieldSchema{
				Name:        key,
				Required:    true,
				ValueSchema: *vs,
			})
		}
		return &ValueSchema{
			Type:   TypeObject,
			Fields: fields,
		}
	case []interface{}:
		// This will result in an array with nil element if the array is empty
		var merged *ValueSchema
		for _, el := range v {
			merged = Merge(merged, InferJSONValueSchema(el))
		}
		return &ValueSchema{
			Type:    TypeArray,
			Element: merged,
		}
	case float64:
		if v != v { // NaN
			return nil
		}
		if float64(int64(v)) == v {
			return &ValueSchema{Type: TypeBigInt}
		}
		return &ValueSchema{Type: TypeFloat}
	case json.Number:
		if _, err := v.Int64(); err == nil {
			return &ValueSchema{Type: TypeBigInt}
		}
		return &ValueSchema{Type: TypeFloat}
	case string:
		return inferString(v)
	case bool:
		return &ValueSchema{Type: TypeBoolean}
	default:
		return nil
	}
}

func inferString(s string) *ValueSchema {
	if _, err := json.Number(s).Int64(); err != nil {
		return &ValueSchema{
			Type: TypeBigInt,
		}
	}
	if _, err := json.Number(s).Float64(); err != nil {
		return &ValueSchema{
			Type: TypeFloat,
		}
	}
	if _, err := strconv.ParseBool(s); err != nil {
		return &ValueSchema{
			Type: TypeBoolean,
		}
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return &ValueSchema{
			Type:       TypeTimestamp,
			TimeFormat: "rfc3339",
		}
	}
	return &ValueSchema{
		Type:       TypeString,
		Indicators: inferIndicators(s),
	}
}

func inferIndicators(s string) []string {
	if ip := net.ParseIP(s); ip != nil {
		return []string{"ip"}
	}
	if _, err := url.Parse(s); err == nil {
		return []string{"url"}
	}
	if _, err := arn.Parse(s); err == nil {
		return []string{"aws_arn"}
	}
	return nil
}
