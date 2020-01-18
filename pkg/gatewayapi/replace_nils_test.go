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

import (
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testResource struct {
	Counts     map[string]int
	Data       interface{}
	IDs        []int
	Names      []string
	Parameters map[string]string
	VersionID  *string
}

type testInner struct {
	BoolSlice []*bool
	IntMap    map[int]*int

	privateMap map[string]*bool
}

type testNested struct {
	testResource            // anonymous embedding
	*testInner              // anonymous pointer embedding
	Inner        *testInner // nested struct ptr
	InnerDirect  testInner  // nested struct
}

type testComplex struct {
	SliceOfMaps   []map[string]bool
	SliceOfSlices [][]int
	MapOfMaps     map[string]map[int]bool
	MapOfSlices   map[string][]int
}

type testAttrs struct {
	Attributes map[string]interface{}
}

// Input is not a pointer
func TestReplaceMapSliceNilsInvalid(t *testing.T) {
	assert.Panics(t, func() { ReplaceMapSliceNils(5) })
	assert.Panics(t, func() { ReplaceMapSliceNils(testResource{}) })
}

// Input is typed or untyped nil
func TestReplaceMapSliceNilsNil(t *testing.T) {
	assert.NotPanics(t, func() { ReplaceMapSliceNils(nil) })
	var resource *testComplex
	assert.NotPanics(t, func() { ReplaceMapSliceNils(resource) })
}

// Standard setup: a struct with nil maps and slices
func TestReplaceMapSliceNils(t *testing.T) {
	var resource interface{} = &testResource{}
	ReplaceMapSliceNils(&resource)
	expected := &testResource{
		Counts:     map[string]int{},
		Data:       nil,
		IDs:        []int{},
		Names:      []string{},
		Parameters: map[string]string{},
	}
	assert.Equal(t, expected, resource)

	// Existing non-nil fields are left intact
	resource = &testResource{
		Counts: map[string]int{"panther": 1, "labs": 2},
		Names:  []string{"panther", "labs", "inc"},
	}
	ReplaceMapSliceNils(resource)
	expected = &testResource{
		Counts:     map[string]int{"panther": 1, "labs": 2},
		Data:       nil,
		IDs:        []int{},
		Names:      []string{"panther", "labs", "inc"},
		Parameters: map[string]string{},
	}
	assert.Equal(t, expected, resource)
}

// Nested and embedded structs
func TestReplaceMapSliceNilsNested(t *testing.T) {
	resource := &testNested{}
	ReplaceMapSliceNils(resource)
	expected := &testNested{
		testResource: testResource{
			Counts:     map[string]int{},
			IDs:        []int{},
			Names:      []string{},
			Parameters: map[string]string{},
		},
		Inner: nil, // nil struct ptr was not replaced
		InnerDirect: testInner{
			BoolSlice:  []*bool{},
			IntMap:     map[int]*int{},
			privateMap: nil,
		},
	}
	assert.Equal(t, expected, resource)

	resource = &testNested{testInner: &testInner{}}
	ReplaceMapSliceNils(resource)
	expected.testInner = &expected.InnerDirect
	assert.Equal(t, expected, resource)
}

// Slices and maps which themselves contain nil slices and maps
func TestReplaceMapSliceNilsComplex(t *testing.T) {
	resource := &testComplex{
		SliceOfMaps:   []map[string]bool{nil, {"panther": true}, nil},
		SliceOfSlices: [][]int{{}, nil, {1, 2, 3}},
		MapOfMaps:     map[string]map[int]bool{"nil": nil, "empty": {}, "panther": {2019: true}},
		MapOfSlices:   map[string][]int{"nil": nil, "empty": {}, "panther": {1, 2, 3}},
	}
	ReplaceMapSliceNils(resource)
	expected := &testComplex{
		SliceOfMaps:   []map[string]bool{{}, {"panther": true}, {}},
		SliceOfSlices: [][]int{{}, {}, {1, 2, 3}},
		MapOfMaps:     map[string]map[int]bool{"nil": {}, "empty": {}, "panther": {2019: true}},
		MapOfSlices:   map[string][]int{"nil": {}, "empty": {}, "panther": {1, 2, 3}},
	}
	assert.Equal(t, expected, resource)
}

func TestUnmarshaledNulls(t *testing.T) {
	data := `{
        "KmsKeyId": null,
		"Snapshots": [
			null,
			null,
			{
				"DataEncryptionKeyId": null,
				"Description": "public-snapshot",
				"State": "completed",
				"StateMessage": null
			}
		],
		"State": "in-use",
		"Tags": null
	}`
	var attrs testAttrs
	require.NoError(t, jsoniter.UnmarshalFromString(data, &attrs.Attributes))

	ReplaceMapSliceNils(&attrs)
	expected := map[string]interface{}{
		"KmsKeyId": nil,
		"Snapshots": []interface{}{
			nil,
			nil,
			map[string]interface{}{
				"DataEncryptionKeyId": nil,
				"Description":         "public-snapshot",
				"State":               "completed",
				"StateMessage":        nil,
			},
		},
		"State": "in-use",
		"Tags":  nil,
	}
	assert.Equal(t, expected, attrs.Attributes)
}
