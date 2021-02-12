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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/pkg/x/structfields"
)

// InferJSONValueSchema infers the Value Schema for a JSON value.
//
// It will return `nil` if `x` is `nil` or if it is not one of the types
// defined in https://golang.org/pkg/encoding/json/#Unmarshal.
// If distinction between integer numbers and float numbers is required, the value should be unmarshalled
// using `json.Number` (e.g. json.Decoder.UseNumber()).
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
				Name: key,
				// The field is marked as required by default.
				// If it is not found in future Merge() calls, it will become optional.
				Required:    true,
				ValueSchema: *vs,
			})
		}
		sort.Slice(fields, func(i, j int) bool {
			return fields[i].Name < fields[j].Name
		})
		return &ValueSchema{
			Type:   TypeObject,
			Fields: fields,
		}
	case []interface{}:
		// This will result in an array with nil element if the array is empty.
		// Future `Merge()` calls will fix that if the type of the element was inferred.
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
	if _, err := json.Number(s).Int64(); err == nil {
		return &ValueSchema{
			Type: TypeBigInt,
		}
	}
	if _, err := json.Number(s).Float64(); err == nil {
		return &ValueSchema{
			Type: TypeFloat,
		}
	}
	if _, err := strconv.ParseBool(s); err == nil {
		return &ValueSchema{
			Type: TypeBoolean,
		}
	}
	if _, err := time.Parse(time.RFC3339, s); err == nil {
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
	if u, err := url.Parse(s); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return []string{"url"}
	}
	if _, err := arn.Parse(s); err == nil {
		return []string{"aws_arn"}
	}
	return nil
}

// NonEmpty scrubs the ValueSchema from any empty object/array schemas.
func (v *ValueSchema) NonEmpty() *ValueSchema {
	if v == nil {
		return nil
	}
	switch v.Type {
	case TypeObject:
		fields := make([]FieldSchema, 0, len(v.Fields))
		for _, f := range v.Fields {
			if v := f.ValueSchema.NonEmpty(); v != nil {
				f.ValueSchema = *v
				fields = append(fields, f)
			}
		}
		if len(fields) == 0 {
			return nil
		}
		return &ValueSchema{
			Type:   TypeObject,
			Fields: fields,
		}
	case TypeArray:
		if el := v.Element.NonEmpty(); el != nil {
			return &ValueSchema{
				Type:    TypeArray,
				Element: el,
			}
		}
		return nil
	case TypeString, TypeTimestamp, TypeBigInt, TypeInt, TypeSmallInt, TypeFloat, TypeJSON, TypeBoolean, TypeRef:
		return v.Clone()
	default:
		return nil
	}
}

func InferTypeValueSchema(typ reflect.Type) (*ValueSchema, error) {
	// Lift pointer indirections
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	// Handle 'special types'
	if valueType, ok := inverseMappings[typ]; ok {
		return &ValueSchema{
			Type: valueType,
		}, nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		// We check with ConvertibleTo for timestamp types defined as `type T time.Time`
		if typ.ConvertibleTo(reflect.TypeOf(time.Time{})) {
			return &ValueSchema{
				Type: TypeTimestamp,
			}, nil
		}
		fields := structfields.Flatten(typ)
		out := &ValueSchema{
			Type:   TypeObject,
			Fields: make([]FieldSchema, len(fields)),
		}
		for i, field := range fields {
			if err := inferFieldSchema(&out.Fields[i], field); err != nil {
				return nil, err
			}
		}
		return out, nil
	case reflect.Slice:
		el, err := InferTypeValueSchema(typ.Elem())
		if err != nil {
			return nil, err
		}
		return &ValueSchema{
			Type:    TypeArray,
			Element: el,
		}, nil
	case reflect.String:
		return &ValueSchema{Type: TypeString}, nil
	case reflect.Float64, reflect.Float32:
		return &ValueSchema{Type: TypeFloat}, nil
	case reflect.Bool:
		return &ValueSchema{Type: TypeBoolean}, nil
	case reflect.Uint, reflect.Uint64, reflect.Int64, reflect.Uint32:
		return &ValueSchema{Type: TypeBigInt}, nil
	case reflect.Int32, reflect.Uint16, reflect.Int:
		return &ValueSchema{Type: TypeInt}, nil
	case reflect.Int8, reflect.Uint8, reflect.Int16:
		return &ValueSchema{Type: TypeSmallInt}, nil
	case reflect.Map:
		return &ValueSchema{Type: TypeJSON}, nil
	default:
		return nil, errors.Errorf("cannot produce schema for %s", typ)
	}
}

func inferFieldSchema(s *FieldSchema, field reflect.StructField) error {
	name, err := structfields.FieldNameJSON(field)
	if err != nil {
		return err
	}
	s.Name = name
	if structfields.IsRequired(field) {
		s.Required = true
	}
	s.Description = structfields.Describe(field)
	value, err := InferTypeValueSchema(field.Type)
	if err != nil {
		return err
	}
	if isEventTime, err := strconv.ParseBool(field.Tag.Get("event_time")); err == nil && isEventTime {
		value.IsEventTime = isEventTime
	}
	value.TimeFormat = field.Tag.Get("tcodec")
	if value.Type == TypeTimestamp {
		value.TimeFormat = "rfc3339"
		if format, ok := field.Tag.Lookup("tcodec"); ok {
			value.TimeFormat = format
		}
	}
	if pantherTag := field.Tag.Get("panther"); pantherTag != "" {
		scanners := strings.Split(pantherTag, ",")
		for _, name := range scanners {
			if name = strings.TrimSpace(name); name != "" {
				value.Indicators = append(value.Indicators, name)
			}
		}
	}
	s.ValueSchema = *value
	return nil
}
