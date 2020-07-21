package pantherlog

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
	"fmt"
	"reflect"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// TagName is used for defining value scan methods on string fields.
const TagName = "panther"

var (
	typStringer   = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
	typString     = reflect.TypeOf("")
	typStringPtr  = reflect.TypeOf((*string)(nil))
	typNullString = reflect.TypeOf(null.String{})
)

type scanValueEncodersExt struct {
	jsoniter.DummyExtension
}

func (ext *scanValueEncodersExt) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		field := binding.Field
		tag, ok := field.Tag().Lookup(TagName)
		if !ok {
			continue
		}
		scanner, _ := LookupScanner(tag)
		if scanner == nil {
			continue
		}
		fieldType := field.Type().Type1()
		// Decorate encoders
		switch {
		case fieldType.ConvertibleTo(typString):
			binding.Encoder = &scanStringEncoder{
				parent:  binding.Encoder,
				scanner: scanner,
			}
		case fieldType.ConvertibleTo(typStringPtr):
			binding.Encoder = &scanStringPtrEncoder{
				parent:  binding.Encoder,
				scanner: scanner,
			}
		case fieldType.ConvertibleTo(typNullString):
			binding.Encoder = &scanNullStringEncoder{
				parent:  binding.Encoder,
				scanner: scanner,
			}
		case reflect.PtrTo(fieldType).Implements(typStringer):
			binding.Encoder = &scanStringerEncoder{
				parent:  binding.Encoder,
				typ:     fieldType,
				scanner: scanner,
			}
		case fieldType.Implements(typStringer):
			indirect := fieldType.Kind() == reflect.Ptr
			binding.Encoder = &scanStringerEncoder{
				parent:   binding.Encoder,
				typ:      fieldType,
				indirect: indirect,
				scanner:  scanner,
			}
		}
	}
}

type scanStringPtrEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

func (enc *scanStringPtrEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}
func (enc *scanStringPtrEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((**string)(ptr))
	if input == nil {
		return
	}
	if result, ok := stream.Attachment.(*Result); ok && result.Values != nil {
		enc.scanner.ScanValues(result.Values, *input)
	}
}

type scanNullStringEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

func (enc *scanNullStringEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

func (enc *scanNullStringEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((*null.String)(ptr))
	if !input.Exists || input.Value == "" {
		return
	}
	if result, ok := stream.Attachment.(*Result); ok && result.Values != nil {
		enc.scanner.ScanValues(result.Values, input.Value)
	}
}

type scanStringerEncoder struct {
	parent   jsoniter.ValEncoder
	scanner  ValueScanner
	typ      reflect.Type
	indirect bool
}

func (enc *scanStringerEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

func (enc *scanStringerEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	result, ok := stream.Attachment.(*Result)
	if !ok || result.Values == nil {
		return
	}
	val := reflect.NewAt(enc.typ, ptr)
	if enc.indirect {
		val = val.Elem()
	}
	str := val.Interface().(fmt.Stringer)
	if input := str.String(); input != "" {
		enc.scanner.ScanValues(result.Values, input)
	}
}

type scanStringEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

func (enc *scanStringEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}
func (enc *scanStringEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((*string)(ptr))
	if input == "" {
		return
	}
	if values, ok := stream.Attachment.(ValueWriter); ok {
		enc.scanner.ScanValues(values, input)
	}
}
