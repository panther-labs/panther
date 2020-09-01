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
	"strconv"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

// Int16 represents a nullable int16 value.
// It parses both string an number JSON values.
type Int16 struct {
	Value  int16
	Exists bool
}

// FromInt16 creates a non-null Int16.
// It is inlined by the compiler.
func FromInt16(n int16) Int16 {
	return Int16{
		Value:  n,
		Exists: true,
	}
}

func (i *Int16) IsNull() bool {
	return !i.Exists
}

// UnmarshalJSON implements json.Unmarshaler interface.
// It decodes Int16 value s from string, number or null JSON input.
func (i *Int16) UnmarshalJSON(data []byte) error {
	// Check null JSON input
	if string(data) == `null` {
		*i = Int16{}
		return nil
	}
	// Handle both string and number input
	data = unquoteJSON(data)
	// Empty string is considered the same as `null` input
	if len(data) == 0 {
		*i = Int16{}
		return nil
	}
	// Read the int16 value
	n, err := strconv.ParseInt(string(data), 10, 16)
	if err != nil {
		return err
	}
	*i = Int16{
		Value:  int16(n),
		Exists: true,
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (i Int16) MarshalJSON() ([]byte, error) {
	if !i.Exists {
		return []byte(`null`), nil
	}
	return strconv.AppendInt(nil, int64(i.Value), 10), nil
}

// int16Codec is a jsoniter encoder/decoder for int16 values
type int16Codec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*int16Codec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullInt16"
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		n := iter.ReadInt16()
		*((*Int16)(ptr)) = Int16{
			Value:  n,
			Exists: noError(iter.Error),
		}
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Int16)(ptr)) = Int16{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Int16)(ptr)) = Int16{}
			return
		}
		n, err := strconv.ParseInt(string(s), 10, 16)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Int16)(ptr)) = Int16{
			Value:  int16(n),
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null int16 value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*int16Codec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if i := (*Int16)(ptr); i.Exists {
		stream.WriteInt16(i.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers only `null` values as empty and omits them
func (*int16Codec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Int16)(ptr)).Exists
}
