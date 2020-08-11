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

type Float64 struct {
	Value  float64
	Exists bool
}

// FromFloat64 creates a non-null Float64.
// It is inlined by the compiler.
func FromFloat64(n float64) Float64 {
	return Float64{
		Value:  n,
		Exists: true,
	}
}

func (f *Float64) IsNull() bool {
	return !f.Exists
}

// UnmarshalJSON implements json.Unmarshaler interface.
// It decodes Float64 value s from string, number or null JSON input.
func (f *Float64) UnmarshalJSON(data []byte) error {
	// Check null JSON input
	if string(data) == `null` {
		*f = Float64{}
		return nil
	}
	// Handle both string and number input
	data = unquoteJSON(data)
	// Empty string is considered the same as `null` input
	if len(data) == 0 {
		*f = Float64{}
		return nil
	}
	// Read the float64 value
	v, err := strconv.ParseFloat(string(data), 64)
	if err != nil {
		return err
	}
	*f = Float64{
		Value:  v,
		Exists: true,
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (f Float64) MarshalJSON() ([]byte, error) {
	if !f.Exists {
		return []byte(`null`), nil
	}
	return json.Marshal(f.Value)
}

// float64Codec is a jsoniter encoder/decoder for float64 values
type float64Codec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*float64Codec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullFloat64"
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		f := iter.ReadFloat64()
		*((*Float64)(ptr)) = Float64{
			Value:  f,
			Exists: noError(iter.Error),
		}
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Float64)(ptr)) = Float64{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Float64)(ptr)) = Float64{}
			return
		}
		f, err := strconv.ParseFloat(string(s), 64)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Float64)(ptr)) = Float64{
			Value:  f,
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null float64 value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*float64Codec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if f := (*Float64)(ptr); f.Exists {
		stream.WriteFloat64(f.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers only `null` values as empty and omits them
func (*float64Codec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Float64)(ptr)).Exists
}
