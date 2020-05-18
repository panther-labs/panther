package null

import (
	"encoding/json"
	"reflect"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

// String is a nullable string value
type String struct {
	Value string
	OK    bool
}

// String implements fmt.Stringer interface
// It is inlined by the compiler.
func (s *String) String() string {
	return s.Value
}

// FromString creates a non-null String.
// It is inlined by the compiler.
func FromString(s string) String {
	return String{
		Value: s,
		OK:    true,
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
	s.OK = true
	return nil
}

// MarshalJSON implements json.Marshaler interface
func (s *String) MarshalJSON() ([]byte, error) {
	if s.OK {
		return json.Marshal(s.Value)
	}
	return nullJSON, nil
}

// nullStringCodec is a jsoniter encoder/decoder for String values
type nullStringCodec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*nullStringCodec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*String)(ptr)) = String{}
	case jsoniter.StringValue:
		*((*String)(ptr)) = String{
			Value: iter.ReadString(),
			OK:    true,
		}
	default:
		iter.ReportError("ReadNullString", "invalid null string value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*nullStringCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if str := (*String)(ptr); str.OK {
		stream.WriteString(str.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
func (*nullStringCodec) IsEmpty(ptr unsafe.Pointer) bool {
	// A String is non empty only when it's non null and it's Value is not ""
	if str := (*String)(ptr); str.OK {
		return str.Value == ""
	}
	return true
}

func init() {
	// Register jsoniter encoder/decoder for String
	typ := reflect.TypeOf((*String)(nil)).Elem()
	jsoniter.RegisterTypeEncoder(typ.String(), &nullStringCodec{})
	jsoniter.RegisterTypeDecoder(typ.String(), &nullStringCodec{})
}
