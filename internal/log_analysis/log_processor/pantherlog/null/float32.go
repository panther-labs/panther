// nolint: dupl
package null

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
	"encoding/json"
	"strconv"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

type Float32 struct {
	Value  float32
	Exists bool
}

// FromFloat32 creates a non-null Float32.
// It is inlined by the compiler.
func FromFloat32(n float32) Float32 {
	return Float32{
		Value:  n,
		Exists: true,
	}
}

func (f *Float32) IsNull() bool {
	return !f.Exists
}

// UnmarshalJSON implements json.Unmarshaler interface.
// It decodes Float32 value s from string, number or null JSON input.
func (f *Float32) UnmarshalJSON(data []byte) error {
	// Check null JSON input
	if string(data) == `null` {
		*f = Float32{}
		return nil
	}
	// Handle both string and number input
	data = unquoteJSON(data)
	// Empty string is considered the same as `null` input
	if len(data) == 0 {
		*f = Float32{}
		return nil
	}
	// Read the float32 value
	v, err := strconv.ParseFloat(string(data), 32)
	if err != nil {
		return err
	}
	*f = Float32{
		Value:  float32(v),
		Exists: true,
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (f Float32) MarshalJSON() ([]byte, error) {
	if !f.Exists {
		return []byte(`null`), nil
	}
	return json.Marshal(f.Value)
}

// float32Codec is a jsoniter encoder/decoder for float32 values
type float32Codec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*float32Codec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullFloat32"
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		f := iter.ReadFloat32()
		*((*Float32)(ptr)) = Float32{
			Value:  f,
			Exists: noError(iter.Error),
		}
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Float32)(ptr)) = Float32{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Float32)(ptr)) = Float32{}
			return
		}
		f, err := strconv.ParseFloat(string(s), 32)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Float32)(ptr)) = Float32{
			Value:  float32(f),
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null float32 value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*float32Codec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if f := (*Float32)(ptr); f.Exists {
		stream.WriteFloat32(f.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers only `null` values as empty and omits them
func (*float32Codec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Float32)(ptr)).Exists
}
