package pantherlog

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
	"reflect"
	"unsafe"
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
