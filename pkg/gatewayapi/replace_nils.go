package gatewayapi

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

import "reflect"

// ReplaceMapSliceNils replaces nil slices and maps with initialized versions.
//
// For example, struct{Tags []string} would serialize as "tags: []" instead of "tags: null"
// The input must be a pointer to a struct.
func ReplaceMapSliceNils(val interface{}) {
	r := reflect.ValueOf(val)
	if !r.IsValid() {
		return // untyped nil
	}

	if r.Kind() != reflect.Ptr {
		// pointer is required for us to actually be able to change values in the struct
		panic("ReplaceMapSliceNils expected pointer, got " + r.Kind().String())
	}
	replaceNilsPtr(r)
}

// Recursively replace nil values for slices and maps.
//
// The modified value is returned in case it needs to be set somewhere by the caller.
func replaceNils(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v // untyped nil
	}

	switch v.Kind() {
	case reflect.Interface:
		return replaceNils(v.Elem())
	case reflect.Map:
		return replaceNilsMap(v)
	case reflect.Ptr:
		return replaceNilsPtr(v)
	case reflect.Slice:
		return replaceNilsSlice(v)
	case reflect.Struct:
		return replaceNilsStruct(v)
	}

	return v
}

func replaceNilsMap(v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.MakeMap(v.Type()) // make a new empty map
	}

	// Iterate over map values, recursively replacing nil slices/maps
	iter := v.MapRange()
	canSet := v.CanSet()
	for iter.Next() {
		mapKey, mapVal := iter.Key(), iter.Value()
		newValue := replaceNils(mapVal)
		if canSet && newValue.IsValid() {
			v.SetMapIndex(mapKey, newValue)
		}
	}

	return v
}

func replaceNilsPtr(v reflect.Value) reflect.Value {
	if !v.IsNil() {
		replaceNils(reflect.Indirect(v))
	}

	return v
}

func replaceNilsSlice(v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.MakeSlice(v.Type(), 0, 0) // make a new 0 capacity slice
	}

	// Iterate over slice elements, recursively replacing nil slices/maps
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		newValue := replaceNils(elem)
		if elem.CanSet() && newValue.IsValid() {
			elem.Set(newValue)
		}
	}

	return v
}

func replaceNilsStruct(v reflect.Value) reflect.Value {
	// Iterate over struct fields, recursively replacing nil slices/maps
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		newValue := replaceNils(field)
		if field.CanSet() && newValue.IsValid() {
			field.Set(newValue)
		}
	}

	return v
}
