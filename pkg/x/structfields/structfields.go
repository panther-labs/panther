package structfields

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
	"fmt"
	"reflect"
	"strings"

	"github.com/fatih/structtag"
)

// Flatten resolves the exported fields of a struct
//
// Fields in embedded structs are recursively resolved and promoted to 'top-level'
func Flatten(typ reflect.Type) []reflect.StructField {
	return appendStructFields(nil, typ)
}

// appendStructFields appends a struct's exported fields to a slice
func appendStructFields(fields []reflect.StructField, typ reflect.Type) []reflect.StructField {
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		// No fields in non-struct types
		return fields
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Anonymous {
			// Possible embedded struct, extend the fields
			fields = appendStructFields(fields, field.Type)
			continue
		}
		// Skip unexported field
		if field.PkgPath != "" {
			continue
		}
		fields = append(fields, field)
	}
	return fields
}

// FieldNameJSON resolves the name a field will have in JSON
func FieldNameJSON(field reflect.StructField) (string, error) {
	tags, err := structtag.Parse(string(field.Tag))
	if err != nil {
		return "", err
	}
	switch tag, err := tags.Get("json"); {
	case err != nil:
		// Field has no JSON struct tag, it uses the same name in JSON
		return field.Name, nil
	case tag.Name == "-":
		// Field is explicitly omitted for JSON
		return "", nil
	default:
		// Use JSON field name for deriving column name
		return tag.Name, nil
	}
}

// IsRequired checks whether a field is required or not.
func IsRequired(field reflect.StructField) bool {
	tag, hasValidate := field.Tag.Lookup("validate")
	if !hasValidate {
		// If the field does not have a 'validate' tag, it is not required
		return false
	}
	// Otherwise, if the 'validate' tag contains 'omitempty' it is not a required field.
	return !strings.Contains(tag, "omitempty")
}

// Describe returns a description for a field
// It looks for a 'description' tag.
// If it is not found it returns a generic description.
func Describe(field reflect.StructField) string {
	desc := field.Tag.Get("description")
	desc = strings.TrimSpace(desc)
	if desc != "" {
		return desc
	}
	if field.Anonymous {
		return "Anonymous field"
	}
	return fmt.Sprintf("%s field", field.Name)
}
