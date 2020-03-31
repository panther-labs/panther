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
	"github.com/stretchr/testify/require"
)

type TestCustomSimpleType int

type TestCustomSliceType []byte

type TestCustomStructType struct {
	Foo int
}

type TestStruct struct {
	Field1 string `description:"test field"`
	Field2 int32  `description:"test field"`

	TagSuppressed int `json:"-" description:"test field"` // should be skipped cuz of tag

	// should not be emitted because they are private
	privateField       int      // nolint
	setOfPrivateFields struct { // nolint
		subField1 int
		subField2 int
	}
}

func (ts *TestStruct) Foo() { // admits to TestInterface
}

type StructToNest struct {
	InheritedField string `description:"test field"`
}
type NestedStruct struct {
	StructToNest             // composed, in this case fields should be inherited
	A            TestStruct  `description:"test field"`
	B            TestStruct  `description:"test field"`
	C            *TestStruct `description:"test field"`
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
		BoolField bool `description:"test field" validate:"required"` // test we can find required tag

		StringField    string  `json:"stringField" description:"test field"`              // test we use json tags
		StringPtrField *string `json:"stringPtrField,omitempty" description:"test field"` // test we use json tags

		IntField    int    `description:"test field"`
		Int8Field   int8   `description:"test field"`
		Int16Field  int16  `description:"test field"`
		Int32Field  int32  `description:"test field"`
		Int64Field  int64  `description:"test field"`
		IntPtrField *int32 `description:"test field"`

		Float32Field    float32  `description:"test field"`
		Float64Field    float64  `description:"test field"`
		Float32PtrField *float32 `description:"test field"`

		StringSlice []string `description:"test field"`

		IntSlice   []int   `description:"test field"`
		Int32Slice []int32 `description:"test field"`
		Int64Slice []int64 `description:"test field"`

		Float32Slice []float32 `description:"test field"`
		Float64Slice []float64 `description:"test field"`

		StructSlice []TestStruct `description:"test field"`

		MapSlice []map[string]string `description:"test field"`

		MapStringToInterface map[string]interface{}       `description:"test field"`
		MapStringToString    map[string]string            `description:"test field"`
		MapStringToStruct    map[string]TestStruct        `description:"test field"`
		MapStringToMap       map[string]map[string]string `description:"test field"`

		StructField       TestStruct   `description:"test field"`
		NestedStructField NestedStruct `description:"test field"`

		CustomTypeField   TestCustomSimpleType `description:"test field"`
		CustomSliceField  TestCustomSliceType  `description:"test field"`
		CustomStructField TestCustomStructType `description:"test field"`
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
		MapStringToMap:       make(map[string]map[string]string),

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
	customSliceTypeMapping := CustomMapping{
		From: reflect.TypeOf(TestCustomSliceType{}),
		To:   "baz",
	}
	customStructTypeMapping := CustomMapping{
		From: reflect.TypeOf(TestCustomStructType{}),
		To:   "bar",
	}

	excpectedCols := []Column{
		{Name: "BoolField", Type: "boolean", Comment: "test field", Required: true}, // test finding required tag
		{Name: "stringField", Type: "string", Comment: "test field"},
		{Name: "stringPtrField", Type: "string", Comment: "test field"},
		{Name: "IntField", Type: nativeIntMapping(), Comment: "test field"},
		{Name: "Int8Field", Type: "tinyint", Comment: "test field"},
		{Name: "Int16Field", Type: "smallint", Comment: "test field"},
		{Name: "Int32Field", Type: "int", Comment: "test field"},
		{Name: "Int64Field", Type: "bigint", Comment: "test field"},
		{Name: "IntPtrField", Type: "int", Comment: "test field"},
		{Name: "Float32Field", Type: "float", Comment: "test field"},
		{Name: "Float64Field", Type: "double", Comment: "test field"},
		{Name: "Float32PtrField", Type: "float", Comment: "test field"},
		{Name: "StringSlice", Type: "array<string>", Comment: "test field"},
		{Name: "IntSlice", Type: "array<" + nativeIntMapping() + ">", Comment: "test field"},
		{Name: "Int32Slice", Type: "array<int>", Comment: "test field"},
		{Name: "Int64Slice", Type: "array<bigint>", Comment: "test field"},
		{Name: "Float32Slice", Type: "array<float>", Comment: "test field"},
		{Name: "Float64Slice", Type: "array<double>", Comment: "test field"},
		{Name: "StructSlice", Type: "array<struct<Field1:string,Field2:int>>", Comment: "test field"},
		{Name: "MapSlice", Type: "array<map<string,string>>", Comment: "test field"},
		{Name: "MapStringToInterface", Type: "map<string,string>", Comment: "test field"}, // special case
		{Name: "MapStringToString", Type: "map<string,string>", Comment: "test field"},
		{Name: "MapStringToStruct", Type: "map<string,struct<Field1:string,Field2:int>>", Comment: "test field"},
		{Name: "MapStringToMap", Type: "map<string,map<string,string>>", Comment: "test field"},
		{Name: "StructField", Type: "struct<Field1:string,Field2:int>", Comment: "test field"},
		{Name: "NestedStructField", Type: "struct<InheritedField:string,A:struct<Field1:string,Field2:int>,B:struct<Field1:string,Field2:int>,C:struct<Field1:string,Field2:int>>", Comment: "test field"}, // nolint
		{Name: "CustomTypeField", Type: "foo", Comment: "test field"},
		{Name: "CustomSliceField", Type: "baz", Comment: "test field"},
		{Name: "CustomStructField", Type: "bar", Comment: "test field"},
	}

	cols := InferJSONColumns(obj, customSimpleTypeMapping, customSliceTypeMapping, customStructTypeMapping)

	resetField(cols) // reset the Field, not needed for tests

	// uncomment to see results
	/*
		for _, col := range cols {
			fmt.Printf("{Name: \"%s\", Type: \"%s\",Comment: "test field"},\n", col.Name, col.Type)
		}
	*/
	assert.Equal(t, excpectedCols, cols, "Expected columns not found")

	// Test using interface
	var testInterface TestInterface = &TestStruct{}
	cols = InferJSONColumns(testInterface)
	resetField(cols) // reset the Field, not needed for tests
	assert.Equal(t, []Column{
		{Name: "Field1", Type: "string", Comment: "test field"},
		{Name: "Field2", Type: "int", Comment: "test field"},
	}, cols, "Interface test failed")
}

type composedStruct struct {
	fooStruct
	Bar string `description:"test field"`
}

type fooStruct struct {
	Foo string `description:"this is Foo field and it is awesome"`
}

func TestComposeStructs(t *testing.T) {
	// test that the columns are correctly inherited
	composition := composedStruct{
		fooStruct: fooStruct{
			Foo: "foo",
		},
		Bar: "bar",
	}
	cols := InferJSONColumns(&composition)
	resetField(cols) // reset the Field, not needed for tests
	expectedColumns := []Column{
		{Name: "Foo", Type: "string", Comment: "this is Foo field and it is awesome"},
		{Name: "Bar", Type: "string", Comment: "test field"},
	}
	require.Equal(t, expectedColumns, cols)
}

func resetField(cols []Column) {
	for i := range cols {
		var empty reflect.StructField
		cols[i].Field = empty
	}
}
