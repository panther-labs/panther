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
	"time"
	"unsafe"

	"github.com/fatih/structtag"
	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

const (
	// TagName is used for defining value scan methods on string fields.
	TagName = "panther"
	// Mark a struct field of type time.Time to set the result timestamp if it is currently zero time.
	// The first field to be decoded will set the event timestamp.
	// This is meant to be used once in a struct.
	// If used multiple times the first field found during JSON parsing will set the event timestamp.
	// This does not affect events that implement EventTimer and have already set their timestamp.
	tagEventTime = "event_time"

	// Add this tag option to `event_time` to force the use of a non-zero timestamp as the event timestamp.
	// For cases where a timestamp is preferable if it exists this will force setting the result timestamp
	// regardless of the order the fields were parsed in JSON. If used, this option *must* be used only once to have
	// predictable results regardless of the order of fields in JSON.
	// Example
	// ```
	// type T struct {
	//   Time time.Time `json:"tm" panther:"event_time,override"`
	//   FallbackTime time.Time `json:"alt_time" panther:"event_time"`
	// }
	// ```
	tagOptionEventTimeOverride = `override`
)

var (
	typValueWriterTo = reflect.TypeOf((*ValueWriterTo)(nil)).Elem()
	typStringer      = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
	typString        = reflect.TypeOf("")
	typStringPtr     = reflect.TypeOf((*string)(nil))
	typNullString    = reflect.TypeOf(null.String{})
	typTime          = reflect.TypeOf(time.Time{})
	typResult        = reflect.TypeOf(Result{})
)

func init() {
	// Since the panther extension does not affect non-panther struct we register it globally
	jsoniter.RegisterExtension(&pantherExt{})
	// Encode all Result instances using our custom encoder
	jsoniter.RegisterTypeEncoder(typResult.String(), &resultEncoder{})
}

// Special encoder for *Result. It extends the event JSON object with all the required Panther fields.
type resultEncoder struct{}

// IsEmpty implements jsoniter.ValEncoder interface
func (*resultEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	result := (*Result)(ptr)
	return result.Event == nil
}

// Encode implements jsoniter.ValEncoder interface
func (e *resultEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	result := (*Result)(ptr)
	// Hack around events with embedded parsers.PantherLog.
	// TODO: Remove this once all parsers are ported to not use parsers.PantherLog
	if result.EventIncludesPantherFields {
		stream.WriteVal(result.Event)
		return
	}

	// Normal result
	values := result.values
	if values == nil {
		result.values = BlankValueBuffer()
	}

	// We swap the attachment after we're done so other code that depends on their set attachment behaves correctly
	att := stream.Attachment
	stream.Attachment = result
	stream.WriteVal(result.Event)
	stream.Attachment = att

	// Extend the JSON object in the stream buffer with the required Panther fields
	e.writePantherFields(result, stream)

	// Recycle value buffer if it was borrowed
	if values == nil {
		result.values.Recycle()
	}
	result.values = values
}

// writePantherFields extends the JSON object buffer with all required Panther fields.
func (*resultEncoder) writePantherFields(r *Result, stream *jsoniter.Stream) {
	// For unit tests it will be useful to be able to write only the panther added field as a 'proper' JSON object
	if !extendJSON(stream.Buffer()) {
		stream.WriteObjectStart()
	}
	stream.WriteObjectField(FieldLogTypeJSON)
	stream.WriteString(r.PantherLogType)
	stream.WriteMore()

	stream.WriteObjectField(FieldRowIDJSON)
	stream.WriteString(r.PantherRowID)
	stream.WriteMore()

	stream.WriteObjectField(FieldEventTimeJSON)
	if eventTime := r.PantherEventTime; eventTime.IsZero() {
		stream.WriteVal(r.PantherParseTime)
	} else {
		stream.WriteVal(eventTime)
	}
	stream.WriteMore()

	stream.WriteObjectField(FieldParseTimeJSON)
	stream.WriteVal(r.PantherParseTime)

	for id, values := range r.values.index {
		if len(values) == 0 || id.IsCore() {
			continue
		}
		fieldName, ok := registeredFieldNamesJSON[id]
		if !ok {
			continue
		}
		stream.WriteMore()
		stream.WriteObjectField(fieldName)
		stream.WriteArrayStart()
		for i, value := range values {
			if i != 0 {
				stream.WriteMore()
			}
			stream.WriteString(value)
		}
		stream.WriteArrayEnd()
	}

	stream.WriteObjectEnd()
}

func extendJSON(data []byte) bool {
	// Swap JSON object closing brace ('}') with comma (',') to extend the object
	if n := len(data) - 1; 0 <= n && n < len(data) && data[n] == '}' {
		data[n] = ','
		return true
	}
	return false
}

type pantherExt struct {
	jsoniter.DummyExtension
}

func (*pantherExt) DecorateEncoder(typ2 reflect2.Type, encoder jsoniter.ValEncoder) jsoniter.ValEncoder {
	typ := typ2.Type1()
	if typ.Kind() != reflect.Ptr && reflect.PtrTo(typ).Implements(typValueWriterTo) {
		return &customEncoder{
			ValEncoder: encoder,
			typ:        typ,
		}
	}
	return encoder
}

// customEncoder decorates the encoders for all values implementing ValueWriter to write the indicator values
// to the `stream.Attachment` if it implements `ValueWriter`
type customEncoder struct {
	jsoniter.ValEncoder
	typ reflect.Type
}

// IsEmpty implements jsoniter.ValEncoder interface
func (e *customEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return e.ValEncoder.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
func (e *customEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	e.ValEncoder.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	if values, ok := stream.Attachment.(ValueWriter); ok {
		val := reflect.NewAt(e.typ, ptr)
		val.Interface().(ValueWriterTo).WriteValuesTo(values)
	}
}

// UpdateStructDescriptor overrides the `DummyExtension` method to implement `jsoniter.Extension` interface.
// We go over the struct fields looking for `panther` tags on time.Time and string-like types and decorate their
// encoders appropriately.
func (ext *pantherExt) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		field := binding.Field
		tag := string(field.Tag())
		tags, err := structtag.Parse(tag)
		if err != nil {
			continue
		}
		pantherTag, err := tags.Get(TagName)
		if err != nil {
			continue
		}
		fieldType := field.Type().Type1()
		switch {
		case ext.updateTimeBinding(binding, pantherTag, fieldType):
			// Decorate with an encoder that assigns time value to Result.EventTime if non-zero
		case ext.updateStringBinding(binding, pantherTag, fieldType):
			// Decorate with an encoder that appends values to indicator fields using registered scanners
		}
	}
}

// Decorate with an encoder that assigns time value to Result.EventTime if non-zero
func (*pantherExt) updateTimeBinding(b *jsoniter.Binding, tag *structtag.Tag, typ reflect.Type) bool {
	if tag.Name != tagEventTime {
		return false
	}
	if !typ.ConvertibleTo(typTime) {
		return false
	}

	b.Encoder = &eventTimeEncoder{
		ValEncoder: b.Encoder,
		override:   tag.HasOption(tagOptionEventTimeOverride),
	}
	return true
}

type eventTimeEncoder struct {
	jsoniter.ValEncoder
	override bool
}

// We add this method so that other extensions that need to modify the encoder can keep our decorations.
// This is used in `tcodec` to modify the underlying encoder.
func (e *eventTimeEncoder) DecorateEncoder(typ reflect2.Type, encoder jsoniter.ValEncoder) jsoniter.ValEncoder {
	if typ.Type1().ConvertibleTo(typTime) {
		return &eventTimeEncoder{
			ValEncoder: encoder,
			override:   e.override,
		}
	}
	return encoder
}

// IsEmpty implements jsoniter.ValEncoder interface
func (e *eventTimeEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return e.ValEncoder.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
func (e *eventTimeEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	e.ValEncoder.Encode(ptr, stream)
	tm := (*time.Time)(ptr)
	if tm.IsZero() {
		return
	}
	if result, ok := stream.Attachment.(*Result); ok {
		if e.override || result.PantherEventTime.IsZero() {
			result.PantherEventTime = *tm
		}
	}
}

// Decorate with an encoder that appends values to indicator fields using registered scanners
func (*pantherExt) updateStringBinding(b *jsoniter.Binding, tag *structtag.Tag, typ reflect.Type) bool {
	scanner, _ := LookupScanner(tag.Name)
	if scanner == nil {
		// We don't affect string fields if no scanner was found
		return false
	}
	// Decorate encoders
	switch {
	case typ.ConvertibleTo(typString):
		b.Encoder = &scanStringEncoder{
			parent:  b.Encoder,
			scanner: scanner,
		}
		return true
	case typ.ConvertibleTo(typStringPtr):
		b.Encoder = &scanStringPtrEncoder{
			parent:  b.Encoder,
			scanner: scanner,
		}
		return true
	case typ.ConvertibleTo(typNullString):
		b.Encoder = &scanNullStringEncoder{
			parent:  b.Encoder,
			scanner: scanner,
		}
		return true
	case reflect.PtrTo(typ).Implements(typStringer):
		b.Encoder = &scanStringerEncoder{
			parent:  b.Encoder,
			typ:     typ,
			scanner: scanner,
		}
		return true
	case typ.Implements(typStringer):
		indirect := typ.Kind() == reflect.Ptr
		b.Encoder = &scanStringerEncoder{
			parent:   b.Encoder,
			typ:      typ,
			indirect: indirect,
			scanner:  scanner,
		}
		return true
	default:
		return false
	}
}

type scanStringPtrEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

// IsEmpty implements jsoniter.ValEncoder interface
func (enc *scanStringPtrEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
func (enc *scanStringPtrEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((**string)(ptr))
	if input == nil {
		return
	}
	if values, ok := stream.Attachment.(ValueWriter); ok {
		enc.scanner.ScanValues(values, *input)
	}
}

type scanNullStringEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

// IsEmpty implements jsoniter.ValEncoder interface
func (enc *scanNullStringEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
func (enc *scanNullStringEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((*null.String)(ptr))
	if !input.Exists || input.Value == "" {
		return
	}
	if values, ok := stream.Attachment.(ValueWriter); ok {
		enc.scanner.ScanValues(values, input.Value)
	}
}

type scanStringerEncoder struct {
	parent   jsoniter.ValEncoder
	scanner  ValueScanner
	typ      reflect.Type
	indirect bool
}

// IsEmpty implements jsoniter.ValEncoder interface
func (enc *scanStringerEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
func (enc *scanStringerEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	values, ok := stream.Attachment.(ValueWriter)
	if !ok {
		return
	}
	val := reflect.NewAt(enc.typ, ptr)
	if enc.indirect {
		val = val.Elem()
	}
	str := val.Interface().(fmt.Stringer)
	if input := str.String(); input != "" {
		enc.scanner.ScanValues(values, input)
	}
}

type scanStringEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

// IsEmpty implements jsoniter.ValEncoder interface
func (enc *scanStringEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

// Encode implements jsoniter.ValEncoder interface
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
