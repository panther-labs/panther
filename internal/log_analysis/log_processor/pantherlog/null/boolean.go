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

// Bool represents a nullable boolean value.
// It accepts 1, "0", "t", "T", "TRUE", true, "true", "True", 0, "0", "f", "F", "FALSE", false, "false", "False".
// It is using the same convensions as `stronv.ParseBool` https://golang.org/pkg/strconv/#ParseBool.
type Bool struct {
	Value  bool
	Exists bool
}

// FromBool creates a non-null Bool.
// It is inlined by the compiler.
func FromBool(b bool) Bool {
	return Bool{
		Value:  b,
		Exists: true,
	}
}

func (b *Bool) IsNull() bool {
	return !b.Exists
}

// UnmarshalJSON implements json.Unmarshaler interface.
// It decodes Bool value s from string, number or null JSON input using strconv.ParseBool.
func (b *Bool) UnmarshalJSON(data []byte) error {
	// Check null JSON input
	if string(data) == `null` {
		*b = Bool{}
		return nil
	}
	// Handle both string and number input
	data = unquoteJSON(data)
	// Empty string is considered the same as `null` input
	if len(data) == 0 {
		*b = Bool{}
		return nil
	}
	// Read the int8 value
	value, err := strconv.ParseBool(string(data))
	if err != nil {
		return err
	}
	*b = Bool{
		Value:  value,
		Exists: true,
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface.
func (b Bool) MarshalJSON() ([]byte, error) {
	if !b.Exists {
		return []byte(`null`), nil
	}
	if b.Value {
		return []byte(`true`), nil
	}
	return []byte(`false`), nil
}

// boolCodec is a jsoniter encoder/decoder for int8 values
type boolCodec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*boolCodec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullBoolean"
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Bool)(ptr)) = Bool{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Bool)(ptr)) = Bool{}
			return
		}
		b, err := strconv.ParseBool(string(s))
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Bool)(ptr)) = Bool{
			Value:  b,
			Exists: true,
		}
	case jsoniter.NumberValue:
		u := iter.ReadUint8()
		switch u {
		case 0:
			*((*Bool)(ptr)) = Bool{
				Value:  false,
				Exists: noError(iter.Error),
			}
		case 1:
			*((*Bool)(ptr)) = Bool{
				Value:  true,
				Exists: noError(iter.Error),
			}
		default:
			iter.ReportError(opName, "invalid null boolean value")
		}
	case jsoniter.BoolValue:
		b := iter.ReadBool()
		*((*Bool)(ptr)) = Bool{
			Value:  b,
			Exists: noError(iter.Error),
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null bool value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*boolCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if b := (*Bool)(ptr); b.Exists {
		stream.WriteBool(b.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers only `null` values as empty and omits them
func (*boolCodec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Bool)(ptr)).Exists
}
