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
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/fatih/structtag"
	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/omitempty"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

func init() {
	// Since the panther extension does not affect non-panther struct we register it globally
	jsoniter.RegisterExtension(&pantherExt{})
	// Encode all Result instances using our custom encoder
	jsoniter.RegisterTypeEncoder(typResult.String(), &resultEncoder{})
}

const (
	// TagNameIndicator is used for defining a field as an indicator field
	TagNameIndicator = "panther"

	// TagEventTime is used for defining a field as an event time
	//
	// Mark a struct field of type time.Time with a `event_time:"true"` tag to set the result timestamp.
	// If multiple timestamps are present in a struct the first one in the order of definition in the struct
	// will set the event timestamp.
	// This does not affect events that implement EventTimer and have already set their timestamp.
	TagNameEventTime = "event_time"
)

var (
	typValueWriterTo = reflect.TypeOf((*ValueWriterTo)(nil)).Elem()
	typStringer      = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
	typByteSlice     = reflect.TypeOf([]byte{})
	typTime          = reflect.TypeOf(time.Time{})
	typResult        = reflect.TypeOf(Result{})
)

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
		stream.Reset(nil)
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

	if r.PantherSourceID != "" {
		stream.WriteMore()
		stream.WriteObjectField(FieldSourceIDJSON)
		stream.WriteVal(r.PantherSourceID)
	}

	if r.PantherSourceLabel != "" {
		stream.WriteMore()
		stream.WriteObjectField(FieldSourceLabelJSON)
		stream.WriteVal(r.PantherSourceLabel)
	}

	for id, values := range r.values.index {
		if len(values) == 0 || id.IsCore() {
			continue
		}
		fieldName, ok := registeredFieldNamesJSON[id]
		if !ok {
			continue
		}
		sort.Strings(values)
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
	// Don't try to do the swap for empty JSON `{}`
	// Note that we have the `n < len(data)` to avoid the runtime check imposed by the go compiler when we do index operations below.
	// This effectively allows the function to be inlined. (Boundary Check Elimination)
	if n := len(data) - 1; 2 <= n && n < len(data) && data[n] == '}' {
		data[n] = ','
		return true
	}
	return false
}

func NewExtension() jsoniter.Extension {
	return &pantherExt{}
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
		tag := field.Tag()
		if isEventTimeTag(tag) {
			// Decorate with an encoder that appends values to indicator fields using registered scanners
			ext.decorateEventTimeField(binding)
		} else if scanners, ok := isIndicatorTag(tag); ok {
			// Decorate with an encoder that appends values to indicator fields using registered scanners
			ext.decorateIndicatorField(binding, scanners...)
		}
	}
}

// Decorate with an encoder that assigns time value to Result.EventTime if non-zero
func (*pantherExt) decorateEventTimeField(b *jsoniter.Binding) {
	if typ := b.Field.Type().Type1(); typ.ConvertibleTo(typTime) {
		b.Encoder = &eventTimeEncoder{
			ValEncoder: b.Encoder,
		}
	}
}

type eventTimeEncoder struct {
	jsoniter.ValEncoder
}

// We add this method so that other extensions that need to modify the encoder can keep our decorations.
// This is used in `tcodec` to modify the underlying encoder.
func (e *eventTimeEncoder) DecorateEncoder(typ reflect2.Type, encoder jsoniter.ValEncoder) jsoniter.ValEncoder {
	if typ.Type1().ConvertibleTo(typTime) {
		return &eventTimeEncoder{
			ValEncoder: encoder,
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
		// We only override the result event time if the tag was `panther:"event_time,override" or
		// if we're the first to set the event time. See usage comments on `tagEventTime` const above.
		if result.PantherEventTime.IsZero() {
			result.PantherEventTime = tm.UTC()
		}
	}
}

func isEventTimeTag(tag reflect.StructTag) (ok bool) {
	tags, err := structtag.Parse(string(tag))
	if err != nil {
		return
	}
	eventTimeTag, err := tags.Get(TagNameEventTime)
	if err != nil {
		return
	}
	ok, _ = strconv.ParseBool(eventTimeTag.Name)
	return
}

func isIndicatorTag(tag reflect.StructTag) (scanners []ValueScanner, ok bool) {
	indicatorTag, ok := tag.Lookup(TagNameIndicator)
	if !ok {
		return
	}
	for _, scannerName := range strings.Split(indicatorTag, ",") {
		scannerName = strings.TrimSpace(scannerName)
		if scanner, _ := LookupScanner(scannerName); scanner != nil {
			scanners = append(scanners, scanner)
		}
	}
	return scanners, len(scanners) > 0
}

// Decorate with an encoder that appends values to indicator fields using registered scanners
func (*pantherExt) decorateIndicatorField(b *jsoniter.Binding, scanners ...ValueScanner) {
	scanner := MultiScanner(scanners...)
	if scanner == nil {
		return
	}
	typ := b.Field.Type().Type1()
	if enc, ok := newIndicatorEncoder(typ, b.Encoder, scanner); ok {
		b.Encoder = enc
		return
	}
	if enc, ok := newSliceIndicatorEncoder(typ, b.Encoder, scanner); ok {
		b.Encoder = enc
		return
	}
}

func buildJSON() jsoniter.API {
	api := jsoniter.Config{
		EscapeHTML: true,
		// We don't need to validate JSON raw messages.
		// This option is useful for raw messages that are produced by go directly and can contain errors.
		// Our `jsoniter.RawMessage` come from decoding the input JSON so if they contained errors the parsers would
		// already have failed to read the input JSON.
		ValidateJsonRawMessage: false,
		SortMapKeys:            true,
		// Use case sensitive keys when decoding
		CaseSensitive: true,
	}.Froze()
	// Force omitempty on all struct fields
	api.RegisterExtension(omitempty.New("json"))
	// Add tcodec using the default registry
	api.RegisterExtension(&tcodec.Extension{})
	// Register pantherlog last so event_time tags work fine
	api.RegisterExtension(NewExtension())
	return api
}

var jsonAPI = buildJSON()

func ConfigJSON() jsoniter.API {
	return jsonAPI
}
