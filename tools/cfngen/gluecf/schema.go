package gluecf

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

// Infers Glue table column types from Go types, recursively descends types

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

const (
	maxCommentLength = 255 // this is the maximum size for a column comment allowed by CloudFormation
)

// Functions to infer schema by reflection

type CustomMapping struct {
	From reflect.Type // type to map (result of reflect.TypeOf() )
	To   string       // glue type to emit
}

// Walk object, create columns using JSON Serde expected types, allow optional custom mappings
func InferJSONColumns(obj interface{}, customMappings ...CustomMapping) (cols []Column) {
	customMappingsTable := make(map[string]string)
	for _, customMapping := range customMappings {
		customMappingsTable[customMapping.From.String()] = customMapping.To
	}

	objValue := reflect.ValueOf(obj)
	objType := objValue.Type()

	// dereference pointers
	if objType.Kind() == reflect.Ptr {
		objType = objType.Elem()
	}

	return inferJSONColumns(objType, customMappingsTable)
}

func inferJSONColumns(t reflect.Type, customMappingsTable map[string]string) (cols []Column) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous { // if composing a struct, treat fields as part of this struct
			cols = append(cols, inferJSONColumns(field.Type, customMappingsTable)...)
		} else {
			fieldName, jsonType, comment, skip := inferStructFieldType(field, customMappingsTable)
			if skip {
				continue
			}
			comment = strings.TrimSpace(comment)
			if len(comment) == 0 {
				panic(fmt.Sprintf("failed to generate CloudFormation for %s: %s does not have the required associated 'description' tag",
					t.String(), fieldName))
			}
			if len(comment) > maxCommentLength { // clip
				comment = comment[:maxCommentLength-3] + "..."
			}
			cols = append(cols, Column{Name: fieldName, Type: jsonType, Comment: comment})
		}
	}
	return cols
}

func inferStructFieldType(sf reflect.StructField, customMappingsTable map[string]string) (fieldName, jsonType, comment string, skip bool) {
	t := sf.Type

	// deference pointers
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	isUnexported := sf.PkgPath != ""
	if sf.Anonymous {
		if isUnexported && t.Kind() != reflect.Struct { // I can't seem to find a way to exercise this block in my tests
			// Ignore embedded fields of unexported non-struct types.
			skip = true
			return
		}
		// Do not ignore embedded fields of unexported struct types
		// since they may have exported fields.
	} else if isUnexported {
		// Ignore unexported non-embedded fields.
		skip = true
		return
	}

	// use json tag name if present
	tag := sf.Tag.Get("json")
	if tag == "-" {
		skip = true
		return
	}

	fieldName, _ = parseTag(tag)
	if fieldName == "" {
		fieldName = sf.Name
	}

	comment = sf.Tag.Get("description")

	if to, found := customMappingsTable[t.String()]; found {
		jsonType = to
		return
	}

	switch t.Kind() { // NOTE: not all possible nestings have been implemented
	case reflect.Slice:

		sliceOfType := t.Elem()
		switch sliceOfType.Kind() {
		case reflect.Struct:
			jsonType = fmt.Sprintf("array<struct<%s>>", inferStruct(sliceOfType, customMappingsTable))
			return
		case reflect.Map:
			jsonType = fmt.Sprintf("array<%s>", inferMap(sliceOfType, customMappingsTable))
			return
		default:
			jsonType = fmt.Sprintf("array<%s>", toJSONType(sliceOfType))
			return
		}

	case reflect.Map:
		return fieldName, inferMap(t, customMappingsTable), comment, skip

	case reflect.Struct:
		if sf.Anonymous { // composed struct, fields part of enclosing struct
			fieldName = ""
			jsonType = inferStruct(t, customMappingsTable)
		} else {
			jsonType = fmt.Sprintf("struct<%s>", inferStruct(t, customMappingsTable))
		}
		return

	default:
		if mappedType, found := customMappingsTable[t.String()]; found {
			jsonType = mappedType
			return
		}

		// simple types
		jsonType = toJSONType(t)
		return
	}
}

// Recursively expand a struct
func inferStruct(structType reflect.Type, customMappingsTable map[string]string) string { // return comma delimited
	// recurse over components to get types
	numFields := structType.NumField()
	var keyPairs []string
	for i := 0; i < numFields; i++ {
		subFieldName, subFieldJSONType, _, subFieldSkip := inferStructFieldType(structType.Field(i), customMappingsTable)
		if subFieldSkip {
			continue
		}
		if subFieldName != "" {
			subFieldName += ":"
		}
		keyPairs = append(keyPairs, subFieldName+subFieldJSONType)
	}
	return strings.Join(keyPairs, ",")
}

// Recursively expand a map
func inferMap(t reflect.Type, customMappingsTable map[string]string) (jsonType string) {
	mapOfType := t.Elem()
	if mapOfType.Kind() == reflect.Struct {
		jsonType = fmt.Sprintf("map<%s,struct<%s>>", t.Key(), inferStruct(mapOfType, customMappingsTable))
		return
	}
	jsonType = fmt.Sprintf("map<%s,%s>", t.Key(), toJSONType(mapOfType))
	return
}

// Primitive mappings
func toJSONType(t reflect.Type) (jsonType string) {
	switch t.String() {
	case "bool":
		jsonType = "boolean"
	case "string":
		jsonType = "string"
	case "int8":
		jsonType = "tinyint"
	case "int16":
		jsonType = "smallint"
	case "int":
		// int is problematic due to definition (at least 32bits ...)
		switch strconv.IntSize {
		case 32:
			jsonType = "int"
		case 64:
			jsonType = "bigint"
		default:
			panic(fmt.Sprintf("Size of native int unexpected: %d", strconv.IntSize))
		}
	case "int32":
		jsonType = "int"
	case "int64":
		jsonType = "bigint"
	case "float32":
		jsonType = "float"
	case "float64":
		jsonType = "double"
	case "interface {}":
		jsonType = "string" // best we can do in this case
	default:
		panic("Cannot map " + t.String())
	}

	return jsonType
}

// parseTag splits a struct field's json tag into its name and
// comma-separated options.
func parseTag(tag string) (string, string) {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx], tag[idx+1:]
	}
	return tag, ""
}
