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
			fieldName, glueType, comment, required, skip := inferStructFieldType(field, customMappingsTable)
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
			cols = append(cols, Column{
				Name:     fieldName,
				Type:     glueType,
				Comment:  comment,
				Required: required,
				Field:    field,
			})
		}
	}
	return cols
}

func inferStructFieldType(sf reflect.StructField, customMappingsTable map[string]string) (fieldName, glueType, comment string,
	required, skip bool) {

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

	required = strings.Contains(sf.Tag.Get("validate"), "required")

	if to, found := customMappingsTable[t.String()]; found {
		glueType = to
		return
	}

	switch t.Kind() { // NOTE: not all possible nestings have been implemented
	case reflect.Slice:

		sliceOfType := t.Elem()
		switch sliceOfType.Kind() {
		case reflect.Struct:
			glueType = fmt.Sprintf("array<struct<%s>>", inferStruct(sliceOfType, customMappingsTable))
			return
		case reflect.Map:
			glueType = fmt.Sprintf("array<%s>", inferMap(sliceOfType, customMappingsTable))
			return
		default:
			glueType = fmt.Sprintf("array<%s>", toGlueType(sliceOfType))
			return
		}

	case reflect.Map:
		return fieldName, inferMap(t, customMappingsTable), comment, required, skip

	case reflect.Struct:
		if sf.Anonymous { // composed struct, fields part of enclosing struct
			fieldName = ""
			glueType = inferStruct(t, customMappingsTable)
		} else {
			glueType = fmt.Sprintf("struct<%s>", inferStruct(t, customMappingsTable))
		}
		return

	default:
		if mappedType, found := customMappingsTable[t.String()]; found {
			glueType = mappedType
			return
		}

		// simple types
		glueType = toGlueType(t)
		return
	}
}

// Recursively expand a struct
func inferStruct(structType reflect.Type, customMappingsTable map[string]string) string { // return comma delimited
	// recurse over components to get types
	numFields := structType.NumField()
	var keyPairs []string
	for i := 0; i < numFields; i++ {
		subFieldName, subFieldGlueType, _, _, subFieldSkip := inferStructFieldType(structType.Field(i), customMappingsTable)
		if subFieldSkip {
			continue
		}
		if subFieldName != "" {
			subFieldName += ":"
		}
		keyPairs = append(keyPairs, subFieldName+subFieldGlueType)
	}
	return strings.Join(keyPairs, ",")
}

// Recursively expand a map
func inferMap(t reflect.Type, customMappingsTable map[string]string) (glueType string) {
	mapOfType := t.Elem()
	if mapOfType.Kind() == reflect.Struct {
		glueType = fmt.Sprintf("map<%s,struct<%s>>", t.Key(), inferStruct(mapOfType, customMappingsTable))
		return
	} else if mapOfType.Kind() == reflect.Map {
		glueType = fmt.Sprintf("map<%s,%s>", t.Key(), inferMap(mapOfType, customMappingsTable))
		return
	}
	glueType = fmt.Sprintf("map<%s,%s>", t.Key(), toGlueType(mapOfType))
	return
}

// Primitive mappings
func toGlueType(t reflect.Type) (glueType string) {
	switch t.String() {
	case "bool":
		glueType = "boolean"
	case "string":
		glueType = "string"
	case "int8":
		glueType = "tinyint"
	case "int16":
		glueType = "smallint"
	case "int":
		// int is problematic due to definition (at least 32bits ...)
		switch strconv.IntSize {
		case 32:
			glueType = "int"
		case 64:
			glueType = "bigint"
		default:
			panic(fmt.Sprintf("Size of native int unexpected: %d", strconv.IntSize))
		}
	case "int32":
		glueType = "int"
	case "int64":
		glueType = "bigint"
	case "float32":
		glueType = "float"
	case "float64":
		glueType = "double"
	case "interface {}":
		glueType = "string" // best we can do in this case
	case "uint8":
		glueType = "smallint" // Athena doesn't have an unsigned integer type
	case "uint16":
		glueType = "int" // Athena doesn't have an unsigned integer type
	case "uint32":
		glueType = "bigint" // Athena doesn't have an unsigned integer type
	default:
		panic("Cannot map " + t.String())
	}

	return glueType
}

// parseTag splits a struct field's json tag into its name and
// comma-separated options.
func parseTag(tag string) (string, string) {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx], tag[idx+1:]
	}
	return tag, ""
}
