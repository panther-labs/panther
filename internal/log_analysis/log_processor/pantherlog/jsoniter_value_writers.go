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
	"reflect"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
)

var (
	typValueWriterTo = reflect.TypeOf((*ValueWriterTo)(nil)).Elem()
)

type customEncodersExt struct {
	jsoniter.DummyExtension
}

func (*customEncodersExt) DecorateEncoder(typ2 reflect2.Type, encoder jsoniter.ValEncoder) jsoniter.ValEncoder {
	typ := typ2.Type1()
	isPtr := typ.Kind() == reflect.Ptr
	if isPtr {
		return encoder
	}
	typPtr := reflect.PtrTo(typ)
	if typPtr.Implements(typValueWriterTo) {
		return &customEncoder{
			ValEncoder: encoder,
			typ:        typ,
		}
	}
	return encoder
}

type customEncoder struct {
	jsoniter.ValEncoder
	typ reflect.Type
}

func (e *customEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return e.ValEncoder.IsEmpty(ptr)
}
func (e *customEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	e.ValEncoder.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	if result, ok := stream.Attachment.(*Result); ok {
		val := reflect.NewAt(e.typ, ptr)
		val.Interface().(ValueWriterTo).WriteValuesTo(&result.Values)
	}
}
