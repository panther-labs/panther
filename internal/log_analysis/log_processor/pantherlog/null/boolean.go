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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
)

type Boolean struct {
	Value  bool
	Exists bool
}

// FromBoolean creates a non-null Boolean.
// It is inlined by the compiler.
func FromBoolean(b bool) Boolean {
	return Boolean{
		Value:  b,
		Exists: true,
	}
}

func (b *Boolean) IsNull() bool {
	return !b.Exists
}

// UnmarshalJSON implements json.Unmarshaler interface.
// It decodes Boolean value s from string, number or null JSON input.
func (b *Boolean) UnmarshalJSON(data []byte) error {
	// Check null JSON input
	if string(data) == `null` {
		*b = Boolean{}
		return nil
	}
	// Handle both string and number input
	data = jsonutil.UnquoteJSON(data)
	// Empty string is considered the same as `null` input
	if len(data) == 0 {
		*b = Boolean{}
		return nil
	}
	// Read the int8 value
	value, err := strconv.ParseBool(string(data))
	if err != nil {
		return err
	}
	*b = Boolean{
		Value:  value,
		Exists: true,
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (b *Boolean) MarshalJSON() ([]byte, error) {
	if !b.Exists {
		return []byte(`null`), nil
	}
	return strconv.AppendBool(nil, b.Value), nil
}

// int8Codec is a jsoniter encoder/decoder for int8 values
type boolCodec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*boolCodec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullBoolean"
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Boolean)(ptr)) = Boolean{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Boolean)(ptr)) = Boolean{}
			return
		}
		b, err := strconv.ParseBool(string(s))
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Boolean)(ptr)) = Boolean{
			Value:  b,
			Exists: true,
		}
	case jsoniter.NumberValue:
		u := iter.ReadUint8()
		if iter.Error != nil {
			return
		}
		switch u {
		case 0:
			*((*Boolean)(ptr)) = Boolean{
				Value:  false,
				Exists: true,
			}
		case 1:
			*((*Boolean)(ptr)) = Boolean{
				Value:  true,
				Exists: true,
			}
		default:
			iter.ReportError(opName, "invalid null boolean value")
		}
	case jsoniter.BoolValue:
		b := iter.ReadBool()
		if iter.Error != nil {
			return
		}
		*((*Boolean)(ptr)) = Boolean{
			Value:  b,
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null bool value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*boolCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if b := (*Boolean)(ptr); b.Exists {
		stream.WriteBool(b.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers only `null` values as empty and omits them
func (*boolCodec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Boolean)(ptr)).Exists
}
