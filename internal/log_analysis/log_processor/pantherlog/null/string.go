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

// String is a nullable string value that retains empty string in the input
// It's useful to handle string JSON values that could be `null` in the incoming log JSON.
// It's `omitempty` behavior when used with `jsoniter` is to only omit `null` in the output
type String struct {
	Value  string
	Exists bool
}

func (s *String) IsNull() bool {
	return !s.Exists
}
func (s *String) String() string {
	return s.Value
}

// NonEmpty is a nullable string value
// It's useful to handle string JSON values that could be `null` in the incoming log JSON.
// It's `omitempty` behavior when used with `jsoniter` is to omit both `""` and `null` in the output
type NonEmpty String

// FromString creates a non-null String.
// It is inlined by the compiler.
func FromString(s string) String {
	return String{
		Value:  s,
		Exists: true,
	}
}

// UnmarshalJSON implements json.Unmarshaler interface
func (s *String) UnmarshalJSON(data []byte) error {
	if string(data) == `null` {
		*s = String{}
		return nil
	}
	if err := json.Unmarshal(data, &s.Value); err != nil {
		return err
	}
	s.Exists = true
	return nil
}

// UnmarshalJSON implements json.Unmarshaler interface
func (s *NonEmpty) UnmarshalJSON(data []byte) error {
	return ((*String)(s)).UnmarshalJSON(data)
}

// MarshalJSON implements json.Marshaler interface
func (s *String) MarshalJSON() ([]byte, error) {
	if s.Exists {
		return json.Marshal(s.Value)
	}
	return []byte(`null`), nil
}

// MarshalJSON implements json.Marshaler interface
// WARNING: Since `json` package has no method of modifying `omitempty` behavior,
// the empty values (`null`, `""`) cannot be omitted when using `json.Marshal`.
// To omit a `null` or empty string we need to use `jsoniter.Marshal`.
func (s *NonEmpty) MarshalJSON() ([]byte, error) {
	return ((*String)(s)).MarshalJSON()
}

// stringCodec is a jsoniter encoder/decoder for String values
type stringCodec struct{}

// Encode implements jsoniter.ValEncoder interface
func (*stringCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if str := (*String)(ptr); str.Exists {
		stream.WriteString(str.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers *only* `null` values as empty and omits them
func (*stringCodec) IsEmpty(ptr unsafe.Pointer) bool {
	// A String is non empty only when it's non null and it's Value is not ""
	if str := (*String)(ptr); str.Exists {
		return false
	}
	return true
}

// Decode implements jsoniter.ValDecoder interface
func (*stringCodec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*String)(ptr)) = String{}
	case jsoniter.StringValue:
		*((*String)(ptr)) = String{
			Value:  iter.ReadString(),
			Exists: noError(iter.Error),
		}
	case jsoniter.BoolValue:
		*((*String)(ptr)) = String{
			Value:  strconv.FormatBool(iter.ReadBool()),
			Exists: noError(iter.Error),
		}
	case jsoniter.NumberValue:
		*((*String)(ptr)) = String{
			Value:  iter.ReadNumber().String(),
			Exists: noError(iter.Error),
		}
	default:
		iter.Skip()
		iter.ReportError("ReadNullString", "invalid null string value")
	}
}

func StringEncoder() jsoniter.ValEncoder {
	return &stringCodec{}
}
func StringDecoder() jsoniter.ValDecoder {
	return &stringCodec{}
}
func NonEmptyEncoder() jsoniter.ValEncoder {
	return &nonEmptyEncoder{}
}

type nonEmptyEncoder struct{}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers *both* `null` and `""` values as empty and omits them
func (*nonEmptyEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	if str := (*NonEmpty)(ptr); str.Exists && str.Value != "" {
		return false
	}
	return true
}

// Encode implements jsoniter.ValEncoder interface
func (*nonEmptyEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if str := (*NonEmpty)(ptr); str.Exists {
		stream.WriteString(str.Value)
	} else {
		stream.WriteNil()
	}
}
