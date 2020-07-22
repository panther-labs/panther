package pantherlog

import (
	jsoniter "github.com/json-iterator/go"
	"reflect"
	"time"
	"unsafe"
)

var (
	typTime = reflect.TypeOf(time.Time{})
)

type eventTimeExt struct {
	jsoniter.DummyExtension
}

func (*eventTimeExt) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		field := binding.Field
		if typ := field.Type().Type1(); typ != typTime {
			continue
		}
		if tag, ok := field.Tag().Lookup(TagName); ok && tag == "event_time" {
			binding.Encoder = &eventTimeEncoder{
				ValEncoder: binding.Encoder,
			}
		}
	}
}

type eventTimeEncoder struct {
	jsoniter.ValEncoder
}

func (e *eventTimeEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return e.ValEncoder.IsEmpty(ptr)
}
func (e *eventTimeEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	e.ValEncoder.Encode(ptr, stream)
	tm := (*time.Time)(ptr)
	if tm.IsZero() {
		return
	}
	if result, ok := stream.Attachment.(*Result); ok && result.EventTime.IsZero() {
		result.EventTime = *tm
	}
}
