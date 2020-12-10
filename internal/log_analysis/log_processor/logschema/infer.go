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
	"io"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
)

func ReadCommonValueSchema(r io.Reader) (*ValueSchema, error) {
	dec := json.NewDecoder(r)
	var out *ValueSchema
	for dec.More() {
		var x interface{}
		if err := dec.Decode(&x); err != nil {
			return nil, err
		}
		if v := InferValueSchema(x); v != nil {
			out = CommonValueSchema(out, v)
		}
		if out != nil && out.Type == TypeJSON {
			return out, nil
		}
	}
	return out, nil
}

func InferValueSchema(x interface{}) *ValueSchema {
	switch x := x.(type) {
	case map[string]interface{}:
		var fields []FieldSchema
		for key, val := range x {
			vs := InferValueSchema(val)
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
		for _, el := range x {
			merged = CommonValueSchema(merged, InferValueSchema(el))
		}
		return &ValueSchema{
			Type:    TypeArray,
			Element: merged,
		}
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return &ValueSchema{Type: TypeBigInt}
		}
		return &ValueSchema{Type: TypeFloat}
	case string:
		return inferString(x)
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

func CommonValueSchema(a, b *ValueSchema) *ValueSchema {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.Type != b.Type {
		return castValue(a, b)
	}
	switch a.Type {
	case TypeObject:
		var fields []FieldSchema
		for _, d := range DiffFields(a.Fields, b.Fields) {
			a, b := d.A, d.B
			switch {
			case a != nil && b != nil:
				val := CommonValueSchema(&a.ValueSchema, &b.ValueSchema)
				fields = append(fields, FieldSchema{
					Name:        a.Name,
					Required:    a.Required && b.Required,
					ValueSchema: *val,
				})
			case a != nil:
				a.Required = false
				fields = append(fields, *a)
			case b != nil:
				b.Required = false
				fields = append(fields, *b)
			}
		}
		return &ValueSchema{
			Type:   TypeObject,
			Fields: fields,
		}
	case TypeArray:
		return &ValueSchema{
			Type:    TypeArray,
			Element: CommonValueSchema(a.Element, b.Element),
		}
	case TypeString:
		if reflect.DeepEqual(a.Indicators, b.Indicators) {
			return a
		}
		return &ValueSchema{
			Type: TypeString,
		}
	default:
		return a
	}
}

func castValue(a, b *ValueSchema) *ValueSchema {
	switch a.Type {
	case TypeString:
		switch b.Type {
		case TypeFloat, TypeBigInt, TypeTimestamp, TypeBoolean:
			return &ValueSchema{Type: TypeString}
		}
	case TypeBigInt:
		switch b.Type {
		case TypeFloat:
			return &ValueSchema{Type: TypeFloat}
		case TypeString, TypeTimestamp, TypeBoolean:
			return &ValueSchema{Type: TypeString}
		}
	case TypeBoolean:
		switch b.Type {
		case TypeFloat, TypeBigInt, TypeTimestamp, TypeString:
			return &ValueSchema{Type: TypeString}
		}
	}
	return &ValueSchema{Type: TypeJSON}
}
