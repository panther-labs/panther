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
)

type indicatorEncoder struct {
	parent   jsoniter.ValEncoder
	typ      reflect.Type
	scanner  ValueScanner
	addr     bool
	indirect bool
}

func newIndicatorEncoder(typ reflect.Type, parent jsoniter.ValEncoder, scanner ValueScanner) (jsoniter.ValEncoder, bool) {
	var addr, indirect bool
	switch {
	case isIndicatorType(typ):
		addr, indirect = false, false
	case isIndicatorType(reflect.PtrTo(typ)):
		addr, indirect = true, false
	case typ.Kind() == reflect.Ptr && isIndicatorType(typ.Elem()):
		addr, indirect = false, true
	default:
		return nil, false
	}
	return &indicatorEncoder{
		parent:   parent,
		typ:      typ,
		scanner:  scanner,
		addr:     addr,
		indirect: indirect,
	}, true
}

func newSliceIndicatorEncoder(typ reflect.Type, parent jsoniter.ValEncoder, scanner ValueScanner) (*sliceIndicatorEncoder, bool) {
	if typ.Kind() != reflect.Slice {
		return nil, false
	}
	var addr, indirect bool
	el := typ.Elem()
	// slice of indicator values
	switch {
	case isIndicatorType(el):
		addr, indirect = false, false
	case isIndicatorType(reflect.PtrTo(el)):
		addr, indirect = true, false
	case el.Kind() == reflect.Ptr && isIndicatorType(el.Elem()):
		addr, indirect = false, true
	default:
		return nil, false
	}
	return &sliceIndicatorEncoder{
		parent:   parent,
		typ:      typ,
		scanner:  scanner,
		indirect: indirect,
		addr:     addr,
	}, true
}

func isIndicatorType(typ reflect.Type) bool {
	return typ.Implements(typStringer) || typ.ConvertibleTo(typByteSlice)
}

// IsEmpty implements jsoniter.ValEncoder interface
func (enc *indicatorEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
func (enc *indicatorEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	vw, ok := stream.Attachment.(ValueWriter)
	if !ok {
		return
	}
	val := reflect.NewAt(enc.typ, ptr)
	if !enc.addr {
		val = val.Elem()
		if enc.indirect {
			if val.IsNil() {
				return
			}
			val = val.Elem()
		}
	}
	s := fmt.Sprint(val.Interface())
	enc.scanner.ScanValues(vw, s)
}

type sliceIndicatorEncoder struct {
	parent   jsoniter.ValEncoder
	typ      reflect.Type
	scanner  ValueScanner
	indirect bool
	addr     bool
}

// IsEmpty implements jsoniter.ValEncoder interface
func (enc *sliceIndicatorEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
func (enc *sliceIndicatorEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	vw, ok := stream.Attachment.(ValueWriter)
	if !ok {
		return
	}
	val := reflect.NewAt(enc.typ, ptr).Elem()
	for i := 0; i < val.Len(); i++ {
		el := val.Index(i)
		if enc.addr {
			el = el.Addr()
		} else if enc.indirect {
			if el.IsNil() {
				continue
			}
			el = el.Elem()
		}
		s := fmt.Sprint(el.Interface())
		enc.scanner.ScanValues(vw, s)
	}
}
