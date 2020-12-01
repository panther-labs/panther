package genericapi

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
