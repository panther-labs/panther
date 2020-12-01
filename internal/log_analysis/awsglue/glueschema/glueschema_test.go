package glueschema_test

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
	"strconv"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

type TestCustomSimpleType int

type TestCustomSliceType []byte

type TestCustomStructType struct {
	Foo int
}

type TestStruct struct {
	Field1 string `description:"test field"`
	Field2 int32  `description:"test field"`
	Remap  string `json:"@remap" description:"remap field"`

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

func TestInferJsonColumnsRemap(t *testing.T) {
	obj := struct { //nolint
		Payload TestStruct `description:"payload"`
	}{}
	expectedCols := []Column{
		{Name: "Payload", Type: "struct<Field1:string,Field2:int,at_sign_remap:string>", Comment: "payload"}, // nolint
	}
	expectedColumnMappings := map[string]string{"field1": "Field1", "field2": "Field2", "at_sign_remap": "at_sign_remap", "payload": "Payload"}
	actualCols, actualMappings, err := InferColumnsWithMappings(obj)
	require.NoError(t, err)
	require.Equal(t, expectedCols, actualCols)
	require.Equal(t, expectedColumnMappings, actualMappings)
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
		RemapField     string  `json:"@remap,omitempty" description:"remap field"`        // test invalid characters are remaped

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

		MapStringToInterface map[string]jsoniter.RawMessage `description:"test field"`
		MapStringToString    map[string]string              `description:"test field"`
		MapStringToStruct    map[string]TestStruct          `description:"test field"`
		MapStringToMap       map[string]map[string]string   `description:"test field"`

		StructField       TestStruct   `description:"test field"`
		NestedStructField NestedStruct `description:"test field"`

		CustomTypeField        TestCustomSimpleType   `description:"test field"`
		SliceOfCustomTypeField []TestCustomSimpleType `description:"test field"`
		CustomSliceField       TestCustomSliceType    `description:"test field"`
		CustomStructField      TestCustomStructType   `description:"test field"`
	}{
		BoolField: true,

		StringField:    s,
		StringPtrField: &s,
		RemapField:     s,

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

		MapStringToInterface: make(map[string]jsoniter.RawMessage),
		MapStringToString:    make(map[string]string),
		MapStringToStruct:    make(map[string]TestStruct),
		MapStringToMap:       make(map[string]map[string]string),

		StructField: TestStruct{},
		NestedStructField: NestedStruct{
			C: &TestStruct{}, // test with ptrs
		},
		SliceOfCustomTypeField: []TestCustomSimpleType{},
	}

	// adjust for native int expected results
	nativeIntMapping := func() Type {
		switch strconv.IntSize {
		case 32:
			return "int"
		case 64:
			return "bigint"
		default:
			panic(fmt.Sprintf("Size of native int unexpected: %d", strconv.IntSize))
		}
	}

	MustRegisterMapping(reflect.TypeOf(simpleTestType), "foo")
	MustRegisterMapping(reflect.TypeOf(TestCustomSliceType{}), "baz")
	MustRegisterMapping(reflect.TypeOf(TestCustomStructType{}), "bar")

	expectedCols := []Column{
		{Name: "BoolField", Type: "boolean", Comment: "test field", Required: true}, // test finding required tag
		{Name: "stringField", Type: "string", Comment: "test field"},
		{Name: "stringPtrField", Type: "string", Comment: "test field"},
		{Name: "at_sign_remap", Type: "string", Comment: "remap field"},
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
		{Name: "IntSlice", Type: ArrayOf(nativeIntMapping()), Comment: "test field"},
		{Name: "Int32Slice", Type: "array<int>", Comment: "test field"},
		{Name: "Int64Slice", Type: "array<bigint>", Comment: "test field"},
		{Name: "Float32Slice", Type: "array<float>", Comment: "test field"},
		{Name: "Float64Slice", Type: "array<double>", Comment: "test field"},
		{Name: "StructSlice", Type: "array<struct<Field1:string,Field2:int,at_sign_remap:string>>", Comment: "test field"},
		{Name: "MapSlice", Type: "array<map<string,string>>", Comment: "test field"},
		{Name: "MapStringToInterface", Type: "map<string,string>", Comment: "test field"}, // special case
		{Name: "MapStringToString", Type: "map<string,string>", Comment: "test field"},
		{Name: "MapStringToStruct", Type: "map<string,struct<Field1:string,Field2:int,at_sign_remap:string>>", Comment: "test field"},
		{Name: "MapStringToMap", Type: "map<string,map<string,string>>", Comment: "test field"},
		{Name: "StructField", Type: "struct<Field1:string,Field2:int,at_sign_remap:string>", Comment: "test field"},
		{Name: "NestedStructField", Type: "struct<InheritedField:string,A:struct<Field1:string,Field2:int,at_sign_remap:string>,B:struct<Field1:string,Field2:int,at_sign_remap:string>,C:struct<Field1:string,Field2:int,at_sign_remap:string>>", Comment: "test field"}, // nolint
		{Name: "CustomTypeField", Type: "foo", Comment: "test field"},
		{Name: "SliceOfCustomTypeField", Type: "array<foo>", Comment: "test field"},
		{Name: "CustomSliceField", Type: "baz", Comment: "test field"},
		{Name: "CustomStructField", Type: "bar", Comment: "test field"},
	}
	expectedStructFieldNames := map[string]string{
		"a":                      "A",
		"at_sign_remap":          "at_sign_remap",
		"b":                      "B",
		"boolfield":              "BoolField",
		"c":                      "C",
		"customslicefield":       "CustomSliceField",
		"customstructfield":      "CustomStructField",
		"customtypefield":        "CustomTypeField",
		"field1":                 "Field1",
		"field2":                 "Field2",
		"float32field":           "Float32Field",
		"float32ptrfield":        "Float32PtrField",
		"float32slice":           "Float32Slice",
		"float64field":           "Float64Field",
		"float64slice":           "Float64Slice",
		"inheritedfield":         "InheritedField",
		"int16field":             "Int16Field",
		"int32field":             "Int32Field",
		"int32slice":             "Int32Slice",
		"int64field":             "Int64Field",
		"int64slice":             "Int64Slice",
		"int8field":              "Int8Field",
		"intfield":               "IntField",
		"intptrfield":            "IntPtrField",
		"intslice":               "IntSlice",
		"mapslice":               "MapSlice",
		"mapstringtointerface":   "MapStringToInterface",
		"mapstringtomap":         "MapStringToMap",
		"mapstringtostring":      "MapStringToString",
		"mapstringtostruct":      "MapStringToStruct",
		"nestedstructfield":      "NestedStructField",
		"sliceofcustomtypefield": "SliceOfCustomTypeField",
		"stringfield":            "stringField",
		"stringptrfield":         "stringPtrField",
		"stringslice":            "StringSlice",
		"structfield":            "StructField",
		"structslice":            "StructSlice",
	}

	cols, mappings, err := InferColumnsWithMappings(obj)
	assert.NoError(t, err)

	// uncomment to see results
	// for _, col := range cols {
	// 	fmt.Printf(`{Name: \"%s\", Type: \"%s\",Comment: "test field"},\n`, col.Name, col.Type)
	// }
	assert.Equal(t, expectedCols, cols, "Expected columns not found")
	assert.Equal(t, expectedStructFieldNames, mappings)

	// Test using interface
	var testInterface TestInterface = &TestStruct{}
	cols, mappings, err = InferColumnsWithMappings(testInterface)
	assert.NoError(t, err)
	assert.Equal(t, []Column{
		{Name: "Field1", Type: "string", Comment: "test field"},
		{Name: "Field2", Type: "int", Comment: "test field"},
		{Name: "at_sign_remap", Type: "string", Comment: "remap field"},
	}, cols, "Interface test failed")

	assert.Equal(t, map[string]string{
		"at_sign_remap": "at_sign_remap",
		"field1":        "Field1",
		"field2":        "Field2",
	}, mappings)
}

type composedStruct struct {
	fooStruct
	Bar string `description:"test field"`
}

type fooStruct struct {
	Foo   string `description:"this is Foo field and it is awesome"`
	Remap string `json:"@remap" description:"this is Remap field and it's naughty"`
}

func TestComposeStructs(t *testing.T) {
	// test that the columns are correctly inherited
	composition := composedStruct{
		fooStruct: fooStruct{
			Foo: "foo",
		},
		Bar: "bar",
	}
	cols, mappings, err := InferColumnsWithMappings(composition)
	require.NoError(t, err)
	expectedColumns := []Column{
		{Name: "Foo", Type: "string", Comment: "this is Foo field and it is awesome"},
		{Name: "at_sign_remap", Type: "string", Comment: "this is Remap field and it's naughty"},
		{Name: "Bar", Type: "string", Comment: "test field"},
	}
	expectedStructFieldNames := map[string]string{
		"at_sign_remap": "at_sign_remap",
		"bar":           "Bar",
		"foo":           "Foo",
	}
	require.Equal(t, expectedColumns, cols)
	require.Equal(t, expectedStructFieldNames, mappings)
}

func TestInferJSONColumns_MapToRawMessage(t *testing.T) {
	type Struct struct {
		Map map[string]pantherlog.RawMessage `description:"some description"`
	}

	cols, mappings, err := InferColumnsWithMappings(Struct{})
	require.NoError(t, err)

	expectedColumns := []Column{
		{Name: "Map", Type: MapOf("string", "string"), Comment: "some description"},
	}
	expectedStructFieldNames := map[string]string{
		"map": "Map",
	}
	require.Equal(t, expectedColumns, cols)
	require.Equal(t, expectedStructFieldNames, mappings)
}

// Tests that the order of field mappings is correct so that queries on top-level fields work as expected.
func TestInferColumnsWithMappingsOrder(t *testing.T) {
	type U struct {
		BarBaz string
		FooBar string
	}
	type T struct {
		FooBar U      `json:"fooBar"`
		BarBaz string `json:"barBaz"`
	}
	cols, mappings, err := InferColumnsWithMappings(T{})
	require.NoError(t, err)

	expectedColumns := []Column{
		{Name: "fooBar", Type: `struct<BarBaz:string,FooBar:string>`, Comment: ""},
		{Name: "barBaz", Type: `string`, Comment: ""},
	}
	expectedStructFieldNames := map[string]string{
		"foobar": "fooBar",
		"barbaz": "barBaz",
	}
	require.Equal(t, expectedColumns, cols)
	require.Equal(t, expectedStructFieldNames, mappings)
}

func TestInferColumnsCustom(t *testing.T) {
	type T struct {
		Foo jsoniter.RawMessage
		Bar *jsoniter.RawMessage
		Baz string
	}
	cols, err := InferColumnsCustom(T{}, func(t reflect.Type) Type {
		if t == reflect.TypeOf(jsoniter.RawMessage{}) {
			return "object"
		}
		return ""
	})
	assert := require.New(t)
	assert.NoError(err)
	assert.Equal([]Column{
		{Name: "Foo", Type: "object"},
		{Name: "Bar", Type: "object"},
		{Name: "Baz", Type: "string"},
	}, cols)
}
