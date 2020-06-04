package awsglue

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

// Infers Glue table column types from Go types, recursively descends types

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

const (
	DefaultMaxCommentLength = 255

	GlueTimestampType   = "timestamp"
	GlueStringType      = "string"
	GlueStringArrayType = "array<string>"
	GlueBigintType      = "bigint"
)

// RegisterMapping should be run in an init() block to register a custom mapping for a value.
func RegisterMapping(x interface{}, glueType string) {
	// Get non-pointer value
	from := reflect.Indirect(reflect.ValueOf(x)).Type()

	GlueMappings = append(GlueMappings, CustomMapping{
		From: from,
		To:   glueType,
	})
}

var (
	// MaxCommentLength is the maximum size for a column comment (clip if larger), public var so it can be set to control output
	MaxCommentLength = DefaultMaxCommentLength

	// GlueMappings for custom Panther types.
	GlueMappings = []CustomMapping{
		{
			From: reflect.TypeOf(jsoniter.RawMessage{}),
			To:   "string",
		},
	}

	// RuleMatchColumns are columns added by the rules engine
	RuleMatchColumns = []Column{
		{
			Name:    "p_rule_id",
			Type:    "string",
			Comment: "Rule id",
		},
		{
			Name:    "p_alert_id",
			Type:    "string",
			Comment: "Alert id",
		},
		{
			Name:    "p_alert_creation_time",
			Type:    "timestamp",
			Comment: "The time the alert was initially created (first match)",
		},
		{
			Name:    "p_alert_update_time",
			Type:    "timestamp",
			Comment: "The time the alert last updated (last match)",
		},
		{
			Name:    "p_rule_tags",
			Type:    "array<string>",
			Comment: "The tags of the rule that generated this alert",
		},
		{
			Name:    "p_rule_reports",
			Type:    "map<string,array<string>>",
			Comment: "The reporting tags of the rule that generated this alert",
		},
	}
)

type Column struct {
	Name     string
	Type     string // this is the Glue type
	Comment  string
	Required bool
}

// Functions to infer schema by reflection

type CustomMapping struct {
	From reflect.Type // type to map (result of reflect.TypeOf() )
	To   string       // glue type to emit
}

// Walks the object creating Glue columns using JSON SerDe expected types. It allows passing custom mappings.
// It also returns a slice with the names of all nested fields. The names of the fields will be used
// to generate the appropriate field mappings in the SERDE properties.
// For more information see: https://aws.amazon.com/premiumsupport/knowledge-center/json-duplicate-key-error-athena-config/
func InferJSONColumns(obj interface{}, customMappings ...CustomMapping) ([]Column, []string) {
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

	cols, names := inferJSONColumns(objType, customMappingsTable)

	// Removing duplicates
	stringSet := map[string]struct{}{}
	for _, name := range names {
		stringSet[name] = struct{}{}
	}
	structFieldNames := make([]string, 0, len(stringSet))
	for key := range stringSet {
		structFieldNames = append(structFieldNames, key)
	}
	// Sorting field names so there are always returned in the same order
	// It's not strong requirement, but makes the API easier to work with
	sort.Strings(structFieldNames)
	return cols, structFieldNames
}

func inferJSONColumns(t reflect.Type, customMappingsTable map[string]string) (cols []Column, structFieldNames []string) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous { // if composing a struct, treat fields as part of this struct
			nestedColumns, nestedFieldNames := inferJSONColumns(field.Type, customMappingsTable)
			cols = append(cols, nestedColumns...)
			structFieldNames = append(structFieldNames, nestedFieldNames...)
		} else {
			fieldName, glueType, comment, nestedFieldNames, required, skip := inferStructFieldType(field, customMappingsTable)
			if skip {
				continue
			}

			cols = append(cols, Column{
				Name:     fieldName,
				Type:     glueType,
				Comment:  clipComment(t, fieldName, comment), // avoid arbitrarily large comments that can break things
				Required: required,
			})
			structFieldNames = append(structFieldNames, nestedFieldNames...)
		}
	}
	return cols, structFieldNames
}

func clipComment(t reflect.Type, fieldName, comment string) string {
	comment = strings.TrimSpace(comment)
	if len(comment) == 0 {
		panic(fmt.Sprintf("failed to generate glue type for %s: %s does not have the required associated 'description' tag",
			t.String(), fieldName))
	}
	if len(comment) > MaxCommentLength { // clip
		comment = comment[:MaxCommentLength-3] + "..."
	}
	return comment
}

func inferStructFieldType(sf reflect.StructField, customMappingsTable map[string]string) (fieldName, glueType, comment string,
	nestedFieldNames []string, required, skip bool) {

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

	// Rewrite field the same way as the jsoniter extension to avoid invalid column names
	fieldName = RewriteFieldName(fieldName)

	comment = sf.Tag.Get("description")

	required = strings.Contains(sf.Tag.Get("validate"), "required")

	if to, found := customMappingsTable[t.String()]; found {
		glueType = to
		return
	}
	var structType string
	switch t.Kind() { // NOTE: not all possible nestings have been implemented
	case reflect.Slice:

		sliceOfType := t.Elem()
		switch sliceOfType.Kind() {
		case reflect.Struct:
			structType, nestedFieldNames = inferStruct(sliceOfType, customMappingsTable)
			glueType = fmt.Sprintf("array<struct<%s>>", structType)
			return
		case reflect.Map:
			structType, nestedFieldNames = inferMap(sliceOfType, customMappingsTable)
			glueType = fmt.Sprintf("array<%s>", structType)
			return
		default:
			glueType = fmt.Sprintf("array<%s>", toGlueType(sliceOfType))
			return
		}

	case reflect.Map:
		glueType, nestedFieldNames = inferMap(t, customMappingsTable)
		return
	case reflect.Struct:
		if sf.Anonymous { // composed struct, fields part of enclosing struct
			fieldName = ""
			glueType, nestedFieldNames = inferStruct(t, customMappingsTable)
		} else {
			structType, nestedFieldNames = inferStruct(t, customMappingsTable)
			glueType = fmt.Sprintf("struct<%s>", structType)
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
// It returns the struct Glue definition and a slice of all the struct's field names (including nested field names)
func inferStruct(structType reflect.Type, customMappingsTable map[string]string) (glueType string, structFieldNames []string) {
	// recurse over components to get types
	numFields := structType.NumField()
	var keyPairs []string
	for i := 0; i < numFields; i++ {
		subType := structType.Field(i)
		subFieldName, subFieldGlueType, _, nestedFieldNames, _, skip := inferStructFieldType(subType, customMappingsTable)
		structFieldNames = append(structFieldNames, nestedFieldNames...)
		if skip {
			continue
		}
		if subFieldName != "" {
			structFieldNames = append(structFieldNames, subFieldName)
			subFieldName += ":"
		}
		keyPairs = append(keyPairs, subFieldName+subFieldGlueType)
	}
	glueType = strings.Join(keyPairs, ",")
	return glueType, structFieldNames
}

// Recursively expand a map
func inferMap(t reflect.Type, customMappingsTable map[string]string) (glueType string, structFieldNames []string) {
	mapOfType := t.Elem()
	if mapOfType.Kind() == reflect.Struct {
		structGlueType, nestedStructFieldNames := inferStruct(mapOfType, customMappingsTable)
		structFieldNames = append(structFieldNames, nestedStructFieldNames...)
		glueType = fmt.Sprintf("map<%s,struct<%s>>", t.Key(), structGlueType)
		return
	} else if mapOfType.Kind() == reflect.Map {
		mapGlueType, nestedMapFieldNames := inferMap(mapOfType, customMappingsTable)
		structFieldNames = append(structFieldNames, nestedMapFieldNames...)
		glueType = fmt.Sprintf("map<%s,%s>", t.Key(), mapGlueType)
		return
	}
	glueType = fmt.Sprintf("map<%s,%s>", t.Key(), toGlueType(mapOfType))
	return glueType, structFieldNames
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
	case "uint64":
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

// NOTE: The mapping should be easy to remember (so no ASCII code etc) and complex enough
// to avoid possible conflicts with other fields.
var fieldNameReplacer = strings.NewReplacer(
	"@", "_at_sign_",
	",", "_comma_",
	"`", "_backtick_",
	"'", "_apostrophe_",
)

func RewriteFieldName(name string) string {
	result := fieldNameReplacer.Replace(name)
	if result == name {
		return name
	}
	return strings.Trim(result, "_")
}
