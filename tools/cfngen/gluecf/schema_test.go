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

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestCustomSimpleType int

type TestCustomStructType struct {
	Foo int
}

type TestStruct struct {
	Field1 string
	Field2 int32

	TagSuppressed int `json:"-"` // should be skipped cuz of tag

	// should not be emitted because they are private
	privateField       int      // nolint
	setOfPrivateFields struct { // nolint
		subField1 int
		subField2 int
	}
}

func (ts *TestStruct) Foo() { // admits to TestInterface
}

type NestedStruct struct {
	A TestStruct
	B TestStruct
	C *TestStruct
}

type TestInterface interface {
	Foo()
}

func TestInferJsonColumns(t *testing.T) {
	// used to test pointers and types
	var s string = "S"
	var i int32 = 1
	var f float32 = 1
	var simpleTestType TestCustomSimpleType

	obj := struct { // nolint
		BoolField bool

		StringField    string  `json:"stringField"`              // test we use json tags
		StringPtrField *string `json:"stringPtrField,omitempty"` // test we use json tags

		IntField    int
		Int8Field   int8
		Int16Field  int16
		Int32Field  int32
		Int64Field  int64
		IntPtrField *int32

		Float32Field    float32
		Float64Field    float64
		Float32PtrField *float32

		StringSlice []string

		IntSlice   []int
		Int32Slice []int32
		Int64Slice []int64

		Float32Slice []float32
		Float64Slice []float64

		StructSlice []TestStruct

		MapSlice []map[string]string

		MapStringToInterface map[string]interface{}
		MapStringToString    map[string]string
		MapStringToStruct    map[string]TestStruct

		StructField       TestStruct
		NestedStructField NestedStruct

		CustomTypeField   TestCustomSimpleType
		CustomStructField TestCustomStructType
	}{
		BoolField: true,

		StringField:    s,
		StringPtrField: &s,

		IntField:    1,
		Int8Field:   1,
		Int16Field:  1,
		Int32Field:  1,
		Int64Field:  1,
		IntPtrField: &i,

		Float32Field:    1,
		Float64Field:    1,
		Float32PtrField: &f,

		StringSlice: []string{"S1", "S2"},

		IntSlice:   []int{1, 2, 3},
		Int32Slice: []int32{1, 2, 3},
		Int64Slice: []int64{1, 2, 3},

		Float32Slice: []float32{1, 2, 3},
		Float64Slice: []float64{1, 2, 3},

		StructSlice: []TestStruct{},

		MapSlice: []map[string]string{
			make(map[string]string),
		},

		MapStringToInterface: make(map[string]interface{}),
		MapStringToString:    make(map[string]string),
		MapStringToStruct:    make(map[string]TestStruct),

		StructField: TestStruct{},
		NestedStructField: NestedStruct{
			C: &TestStruct{}, // test with ptrs
		},
	}

	// adjust for native int expected results
	nativeIntMapping := func() string {
		switch strconv.IntSize {
		case 32:
			return "int"
		case 64:
			return "bigint"
		default:
			panic(fmt.Sprintf("Size of native int unexpected: %d", strconv.IntSize))
		}
	}

	customSimpleTypeMapping := CustomMapping{
		From: reflect.TypeOf(simpleTestType),
		To:   "foo",
	}
	customStructTypeMapping := CustomMapping{
		From: reflect.TypeOf(TestCustomStructType{}),
		To:   "bar",
	}

	excpectedCols := []Column{
		{Name: "BoolField", Type: "boolean"},
		{Name: "stringField", Type: "string"},
		{Name: "stringPtrField", Type: "string"},
		{Name: "IntField", Type: nativeIntMapping()},
		{Name: "Int8Field", Type: "tinyint"},
		{Name: "Int16Field", Type: "smallint"},
		{Name: "Int32Field", Type: "int"},
		{Name: "Int64Field", Type: "bigint"},
		{Name: "IntPtrField", Type: "int"},
		{Name: "Float32Field", Type: "float"},
		{Name: "Float64Field", Type: "double"},
		{Name: "Float32PtrField", Type: "float"},
		{Name: "StringSlice", Type: "array<string>"},
		{Name: "IntSlice", Type: "array<" + nativeIntMapping() + ">"},
		{Name: "Int32Slice", Type: "array<int>"},
		{Name: "Int64Slice", Type: "array<bigint>"},
		{Name: "Float32Slice", Type: "array<float>"},
		{Name: "Float64Slice", Type: "array<double>"},
		{Name: "StructSlice", Type: "array<struct<Field1:string,Field2:int>>"},
		{Name: "MapSlice", Type: "array<map<string,string>>"},
		{Name: "MapStringToInterface", Type: "map<string,string>"}, // special case
		{Name: "MapStringToString", Type: "map<string,string>"},
		{Name: "MapStringToStruct", Type: "map<string,struct<Field1:string,Field2:int>>"},
		{Name: "StructField", Type: "struct<Field1:string,Field2:int>"},
		{Name: "NestedStructField", Type: "struct<A:struct<Field1:string,Field2:int>,B:struct<Field1:string,Field2:int>,C:struct<Field1:string,Field2:int>>"}, // nolint
		{Name: "CustomTypeField", Type: "foo"},
		{Name: "CustomStructField", Type: "bar"},
	}

	cols := InferJSONColumns(obj, customSimpleTypeMapping, customStructTypeMapping)

	// uncomment to see results
	/*
		for _, col := range cols {
			fmt.Printf("{Name: \"%s\", Type: \"%s\"},\n", col.Name, col.Type)
		}
	*/
	assert.Equal(t, excpectedCols, cols, "Expected columns not found")

	// Test using interface
	var testInterface TestInterface = &TestStruct{}
	cols = InferJSONColumns(testInterface)
	assert.Equal(t, []Column{{Name: "Field1", Type: "string"}, {Name: "Field2", Type: "int"}}, cols, "Interface test failed")
}
