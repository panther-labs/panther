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
	"github.com/panther-labs/panther/pkg/x/structfields"
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
	// used in InferGoTypeValueSchema
	inverseMappings = func() map[reflect.Type]ValueType {
		m := make(map[reflect.Type]ValueType)
		for valueType, goType := range typeMappings {
			m[goType] = valueType
		}
		return m
	}()
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
	var parts []string
	name := fieldNameJSON(schema)
	if name == "" {
		name = "-"
	}
	parts = append(parts, structfields.FormatTag("json", name, "omitempty"))
	parts = append(parts, buildValidate(schema))
	parts = extendStructTag(parts, &schema.ValueSchema)
	desc := normalizeSpace(schema.Description)
	if desc == "" {
		desc = schema.Name
	}
	parts = append(parts, structfields.FormatTag("description", desc))
	return reflect.StructTag(strings.Join(parts, " "))
}

func buildValidate(s *FieldSchema) string {
	var rules []string
	// The precedence is Allow > Deny
	if v := s.Validate; v != nil {
		if len(v.Allow) > 0 {
			rules = append(rules, formatRule("eq", v.Allow...))
		} else if len(v.Deny) > 0 {
			rules = append(rules, formatRule("ne", v.Deny...))
		}
	}
	if s.Required {
		return structfields.FormatTag("validate", "required", rules...)
	}
	if len(rules) == 0 {
		return ""
	}
	return structfields.FormatTag("validate", "omitempty", rules...)
}

func formatRule(op string, values ...string) string {
	rule := make([]string, len(values))
	for i, v := range values {
		// We need to escape , and | to make sure validation rule syntax is not broken
		v = strings.ReplaceAll(v, ",", "0x2C")
		v = strings.ReplaceAll(v, "|", "0x7C")
		rule[i] = op + "=" + v
	}
	return strings.Join(rule, "|")
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

func extendStructTag(parts []string, schema *ValueSchema) []string {
	switch schema.Type {
	case TypeArray:
		return extendStructTag(parts, schema.Element)
	case TypeString:
		if len(schema.Indicators) > 0 {
			parts = append(parts, structfields.FormatTag("panther", schema.Indicators[0], schema.Indicators[1:]...))
		}
		return parts
	case TypeTimestamp:
		if schema.IsEventTime {
			parts = append(parts, structfields.FormatTag("event_time", "true"))
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
		return append(parts, structfields.FormatTag("tcodec", codec))
	default:
		return parts
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
