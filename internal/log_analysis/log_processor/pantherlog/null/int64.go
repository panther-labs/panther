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

// Int64 represents a nullable int64 value.
// It parses both string an number JSON values.
type Int64 struct {
	Value  int64
	Exists bool
}

// FromInt64 creates a non-null Int64.
// It is inlined by the compiler.
func FromInt64(n int64) Int64 {
	return Int64{
		Value:  n,
		Exists: true,
	}
}

func (i *Int64) IsNull() bool {
	return !i.Exists
}

// UnmarshalJSON implements json.Unmarshaler interface.
// It decodes Int64 value s from string, number or null JSON input.
func (i *Int64) UnmarshalJSON(data []byte) error {
	// Check null JSON input
	if string(data) == `null` {
		*i = Int64{}
		return nil
	}
	// Handle both string and number input
	data = unquoteJSON(data)
	// Empty string is considered the same as `null` input
	if len(data) == 0 {
		*i = Int64{}
		return nil
	}
	// Read the int64 value
	n, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	*i = Int64{
		Value:  n,
		Exists: true,
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (i Int64) MarshalJSON() ([]byte, error) {
	if !i.Exists {
		return []byte(`null`), nil
	}
	return strconv.AppendInt(nil, i.Value, 10), nil
}

// int64Codec is a jsoniter encoder/decoder for int64 values
type int64Codec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*int64Codec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullInt64"
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		n := iter.ReadInt64()
		*((*Int64)(ptr)) = Int64{
			Value:  n,
			Exists: noError(iter.Error),
		}
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Int64)(ptr)) = Int64{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Int64)(ptr)) = Int64{}
			return
		}
		n, err := strconv.ParseInt(string(s), 10, 64)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Int64)(ptr)) = Int64{
			Value:  n,
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null int64 value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*int64Codec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if i := (*Int64)(ptr); i.Exists {
		stream.WriteInt64(i.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers only `null` values as empty and omits them
func (*int64Codec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Int64)(ptr)).Exists
}
