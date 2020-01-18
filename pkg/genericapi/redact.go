package genericapi

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"reflect"
	"strconv"
	"strings"
	"time"
)

var timeType = reflect.TypeOf(time.Time{})

// Recursively converts the input to a redacted json map for logging.
func redactedInput(input reflect.Value) interface{} {
	// time.Time is a struct with private fields - we just want to log it as a string.
	if input.Type() == timeType {
		return input.Interface().(time.Time).Format(time.RFC3339)
	}

	switch input.Kind() {
	// Cases are arranged in order of likelihood for optimal efficiency.
	case reflect.Ptr:
		return redactedPtr(input)
	case reflect.Struct:
		return redactedStruct(input)
	case reflect.Slice:
		return redactedSlice(input)
	case reflect.Map:
		return redactedMap(input)
	case reflect.Array:
		return redactedArray(input)
	default:
		return input.Interface()
	}
}

func redactedArray(input reflect.Value) []interface{} {
	length := input.Len()
	result := make([]interface{}, length)
	for i := 0; i < length; i++ {
		result[i] = redactedInput(input.Index(i))
	}
	return result
}

func redactedMap(input reflect.Value) map[interface{}]interface{} {
	if input.IsNil() {
		return nil
	}
	result := make(map[interface{}]interface{}, input.Len())
	iter := input.MapRange()
	for iter.Next() {
		result[iter.Key().Interface()] = redactedInput(iter.Value())
	}
	return result
}

func redactedPtr(input reflect.Value) interface{} {
	if input.IsNil() {
		return nil
	}
	return redactedInput(reflect.Indirect(input))
}

func redactedSlice(input reflect.Value) []interface{} {
	if input.IsNil() {
		return nil
	}
	return redactedArray(input)
}

func redactedStruct(input reflect.Value) map[string]interface{} {
	inputType := input.Type()
	numFields := input.NumField()
	result := make(map[string]interface{}, numFields)
	for i := 0; i < numFields; i++ {
		fieldType := inputType.Field(i)

		// Skip unexported fields
		if fieldType.PkgPath != "" && !fieldType.Anonymous {
			continue
		}

		if fieldType.Tag.Get("genericapi") == "redact" {
			result[fieldName(fieldType)] = redactedField(input.Field(i))
		} else {
			result[fieldName(fieldType)] = redactedInput(input.Field(i))
		}
	}

	return result
}

// fieldName uses the json name when logging the field if available.
func fieldName(field reflect.StructField) string {
	json := strings.SplitN(field.Tag.Get("json"), ",", 2) // e.g. `json:"myFieldName,omitempty"`
	if len(json) == 0 || json[0] == "" {
		return field.Name // default to the name of the field in the struct itself
	}
	return json[0]
}

// A redacted struct field is either nil or e.g. "(redacted slice len=10)"
func redactedField(input reflect.Value) interface{} {
	kind := input.Kind()
	if (kind == reflect.Map || kind == reflect.Ptr || kind == reflect.Slice) && input.IsNil() {
		return nil // nil fields are always logged as such, even if they are otherwise redacted
	}

	switch kind {
	case reflect.Ptr:
		return redactedField(reflect.Indirect(input))
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return "(redacted " + kind.String() + " len=" + strconv.Itoa(input.Len()) + ")"
	default:
		return "(redacted " + kind.String() + ")"
	}
}
