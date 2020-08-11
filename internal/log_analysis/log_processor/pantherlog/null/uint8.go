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

// Uint8 represents a nullable uint8 value.
// It parses both string an number JSON values.
type Uint8 struct {
	Value  uint8
	Exists bool
}

// FromUint8 creates a non-null Uint8.
// It is inlined by the compiler.
func FromUint8(n uint8) Uint8 {
	return Uint8{
		Value:  n,
		Exists: true,
	}
}

func (u *Uint8) IsNull() bool {
	return !u.Exists
}

// UnmarshalJSON implements json.Unmarshaler interface.
// It decodes Int8 value s from string, number or null JSON input.
func (u *Uint8) UnmarshalJSON(data []byte) error {
	// Check null JSON input
	if string(data) == `null` {
		*u = Uint8{}
		return nil
	}
	// Handle both string and number input
	data = unquoteJSON(data)
	// Empty string is considered the same as `null` input
	if len(data) == 0 {
		*u = Uint8{}
		return nil
	}
	// Read the int8 value
	n, err := strconv.ParseUint(string(data), 10, 8)
	if err != nil {
		return err
	}
	*u = Uint8{
		Value:  uint8(n),
		Exists: true,
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (u Uint8) MarshalJSON() ([]byte, error) {
	if !u.Exists {
		return []byte(`null`), nil
	}
	return strconv.AppendUint(nil, uint64(u.Value), 10), nil
}

// uint8Codec is a jsoniter encoder/decoder for integer values
type uint8Codec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*uint8Codec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullUint8"
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		n := iter.ReadUint8()
		*((*Uint8)(ptr)) = Uint8{
			Value:  n,
			Exists: noError(iter.Error),
		}
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Uint8)(ptr)) = Uint8{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Uint8)(ptr)) = Uint8{}
			return
		}
		n, err := strconv.ParseUint(string(s), 10, 8)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Uint8)(ptr)) = Uint8{
			Value:  uint8(n),
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null uint8 value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*uint8Codec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if u := (*Uint8)(ptr); u.Exists {
		stream.WriteUint8(u.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers `null` values as empty and omits them
func (*uint8Codec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Uint8)(ptr)).Exists
}
