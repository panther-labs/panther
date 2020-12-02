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
	"bufio"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// This file provides utils conversion from logschema.ValueSchema to go reflect.Type
// It is separated in the customlogs module to avoid 'leaking' customlogs logic to OSS

var (
	typeMappings = map[ValueType]reflect.Type{
		TypeString:    reflect.TypeOf(pantherlog.String{}),
		TypeBigInt:    reflect.TypeOf(pantherlog.Int64{}),
		TypeInt:       reflect.TypeOf(pantherlog.Int32{}),
		TypeFloat:     reflect.TypeOf(pantherlog.Float64{}),
		TypeSmallInt:  reflect.TypeOf(pantherlog.Int16{}),
		TypeJSON:      reflect.TypeOf(pantherlog.RawMessage{}),
		TypeBoolean:   reflect.TypeOf(pantherlog.Bool{}),
		TypeTimestamp: reflect.TypeOf(pantherlog.Time{}),
	}
)

func (v *ValueSchema) GoType() (reflect.Type, error) {
	if v == nil {
		return nil, fmt.Errorf("nil value")
	}
	switch v.Type {
	case TypeObject:
		fields, err := objectFields(v.Fields)
		if err != nil {
			return nil, err
		}
		str := reflect.StructOf(fields)
		// structs are always ptr
		return reflect.PtrTo(str), nil
	case TypeArray:
		el, err := v.Element.GoType()
		if err != nil {
			return nil, err
		}
		return reflect.SliceOf(el), nil
	default:
		if typ := typeMappings[v.Type]; typ != nil {
			return typ, nil
		}
		return nil, errors.Errorf(`empty value schema %q`, v.Type)
	}
}

func objectFields(schema []FieldSchema) ([]reflect.StructField, error) {
	var fields []reflect.StructField
	for i, field := range schema {
		field := field
		typ, err := field.ValueSchema.GoType()
		if err != nil {
			return nil, err
		}
		fields = append(fields, reflect.StructField{
			Name:  "Field_" + strconv.Itoa(i) + "_" + fieldNameGo(field.Name),
			Type:  typ,
			Tag:   buildStructTag(&field),
			Index: []int{i},
		})
	}
	return fields, nil
}

var reInvalidChars = regexp.MustCompile(`[^A-Za-z0-9_]`)

func fieldNameGo(name string) string {
	name = reInvalidChars.ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	// Fix leading number
	if len(name) > 0 && '0' <= name[0] && name[0] <= '9' {
		name = "Field_" + name
	}
	// UpperCase first letter so it serializes to JSON
	return strings.Title(name)
}

func buildStructTag(schema *FieldSchema) reflect.StructTag {
	name := fieldNameJSON(schema)
	if name == "" {
		name = "-"
	}
	tag := fmt.Sprintf(`json:"%s,omitempty"`, name)
	if schema.Required {
		tag += ` validate:"required"`
	}
	tag = extendStructTag(&schema.ValueSchema, tag)
	desc := normalizeSpace(schema.Description)
	if desc == "" {
		desc = schema.Name
	}
	tag += fmt.Sprintf(` description:"%s"`, desc)
	return reflect.StructTag(tag)
}

func normalizeSpace(input string) string {
	r := bufio.NewScanner(strings.NewReader(input))
	var nonEmptyLines []string
	for r.Scan() {
		line := r.Text()
		line = strings.TrimSpace(line)
		if line != "" {
			nonEmptyLines = append(nonEmptyLines, line)
		}
	}
	return strings.Join(nonEmptyLines, " ")
}

func extendStructTag(schema *ValueSchema, tag string) string {
	switch schema.Type {
	case TypeArray:
		return extendStructTag(schema.Element, tag)
	case TypeString:
		if len(schema.Indicators) == 0 {
			return tag
		}
		return tag + fmt.Sprintf(` panther:"%s"`, strings.Join(schema.Indicators, ","))
	case TypeTimestamp:
		if schema.IsEventTime {
			tag = tag + ` event_time:"true"`
		}
		var codec string
		switch timeFormat := schema.TimeFormat; timeFormat {
		case "rfc3339", "unix", "unix_ms", "unix_us", "unix_ns":
			codec = timeFormat
		case "":
			// Use rfc3339 as the default codec.
			// Keep this in case we decide to make `timeFormat`/`customTimeFormat` optional.
			codec = "rfc3339"
		default:
			codec = "strftime=" + timeFormat
		}
		return tag + fmt.Sprintf(` tcodec:"%s"`, codec)
	default:
		return tag
	}
}

func fieldNameJSON(schema *FieldSchema) string {
	data, _ := json.Marshal(schema.Name)
	return string(unquoteJSON(data))
}

func unquoteJSON(data []byte) []byte {
	if len(data) > 1 && data[0] == '"' {
		data = data[1:]
		if n := len(data) - 1; 0 <= n && n < len(data) && data[n] == '"' {
			return data[:n]
		}
	}
	return data
}
