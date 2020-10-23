package tcodec

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
	"strings"
	"time"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
)

// Extension is a jsoniter.Extension that decodes JSON values to time.Time and encodes back to JSON.
// The extension reads `tcodec` struct tags and matches to registered TimeCodecs.
// ```
// type Foo struct {
//   Timestamp time.Time `json:"ts" tcodec:"rfc3339"`
// }
// ```
//
// To decode/encode a field using a specific layout use `layout=GO_TIME_LAYOUT` tag value.
//
// ```
// type Foo struct {
//   CustomTimestamp time.Time `json:"ts_custom" tcodec:"layout=2006/01/02 15:04"`
// }
// ```
//
type Extension struct {
	jsoniter.DummyExtension

	// Codecs overrides the TimeCodec registry to use for resolving TimeCodecs.
	// If this option is `nil` the default registry is used.
	Codecs *Registry
	// TagName sets the struct tag name to use for tcodec options.
	// If this option is not set the `DefaultTagName` will be used.
	TagName string
}

// DefaultTagName is the struct tag name used for defining time decoders for a time.Time field.
const DefaultTagName = "tcodec"

var (
	typTime    = reflect.TypeOf(time.Time{})
	typTimePtr = reflect.PtrTo(typTime)
)

func (ext *Extension) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	tagName := ext.tagName()
	for _, binding := range desc.Fields {
		field := binding.Field

		typ := field.Type().Type1()
		switch typ {
		case typTime, typTimePtr:
		default:
			// We only affect time.Time and *time.Time fields
			continue
		}
		tag, ok := field.Tag().Lookup(tagName)
		if !ok {
			// We only affect fields that have the tag
			continue
		}
		// convert tag to TimeCodec
		codec, err := ext.resolveCodec(tag)
		if err != nil {
			// Report failed lookup error on decode/encode
			jsonCodec := &errCodec{
				err:       err,
				operation: "LookupTimeCodec",
			}
			binding.Decoder, binding.Encoder = jsonCodec, jsonCodec
			continue
		}

		tDec, tEnc := Split(codec)

		// Preserve decorations of the current binding.Decoder
		vDec := NewTimeDecoder(tDec, typ)
		if ddc, ok := binding.Decoder.(DecoderDecorator); ok {
			vDec = ddc.DecorateDecoder(field.Type(), vDec)
		}

		// Preserve decorations of the current binding.Encoder
		vEnc := NewTimeEncoder(tEnc, typ)
		if edc, ok := binding.Encoder.(EncoderDecorator); ok {
			vEnc = edc.DecorateEncoder(field.Type(), vEnc)
		}

		binding.Decoder, binding.Encoder = vDec, vEnc
	}
}

type DecoderDecorator interface {
	DecorateDecoder(typ reflect2.Type, dec jsoniter.ValDecoder) jsoniter.ValDecoder
}
type EncoderDecorator interface {
	DecorateEncoder(typ reflect2.Type, dec jsoniter.ValEncoder) jsoniter.ValEncoder
}

func (ext *Extension) resolveCodec(tag string) (TimeCodec, error) {
	if strings.HasPrefix(tag, "layout=") {
		// The tag is of the form `layout=GO_TIME_LAYOUT`.
		// We strip the prefix and use a LayoutCodec.
		layout := strings.TrimPrefix(tag, "layout=")
		return LayoutCodec(layout), nil
	}
	if strings.HasPrefix(tag, "strftime=") {
		// The tag is of the form `strftime=STRFTIME_LAYOUT`.
		// We strip the prefix and use a StrftimeCodec.
		layout := strings.TrimPrefix(tag, "strftime=")
		return StrftimeCodec(layout), nil
	}
	if codecs := ext.Codecs; codecs != nil {
		if codec := codecs.Lookup(tag); codec != nil {
			return codec, nil
		}
	}
	if codec := Lookup(tag); codec != nil {
		return codec, nil
	}
	return nil, fmt.Errorf(`failed to resolve %q time codec`, tag)
}

func (ext *Extension) tagName() string {
	if tagName := ext.TagName; tagName != "" {
		return tagName
	}
	return DefaultTagName
}

type jsonTimeEncoder struct {
	encode TimeEncoderFunc
}

func (*jsonTimeEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return (*time.Time)(ptr).IsZero()
}
func (enc *jsonTimeEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	tm := *((*time.Time)(ptr))
	enc.encode(tm, stream)
}

type jsonTimePtrEncoder struct {
	encode TimeEncoderFunc
}

func (*jsonTimePtrEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	tm := *((**time.Time)(ptr))
	return tm == nil || tm.IsZero()
}

func (enc *jsonTimePtrEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	tm := *((**time.Time)(ptr))
	if tm != nil {
		enc.encode(*tm, stream)
	} else {
		stream.WriteNil()
	}
}

type jsonTimeDecoder struct {
	decode TimeDecoderFunc
}

func (dec *jsonTimeDecoder) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	*((*time.Time)(ptr)) = dec.decode(iter)
}

type jsonTimePtrDecoder struct {
	decode TimeDecoderFunc
	typ    reflect.Type
}

func (dec *jsonTimePtrDecoder) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	tm := dec.decode(iter)
	pt := *(**time.Time)(ptr)
	if pt != nil {
		if tm.IsZero() {
			*(**time.Time)(ptr) = nil
		} else {
			*pt = tm
		}
		return
	}
	if tm.IsZero() {
		return
	}
	v := reflect.New(dec.typ)
	// We avoid using reflect.Set to be able to handle embedded timestamps
	newPtr := unsafe.Pointer(v.Pointer())
	*(*time.Time)(newPtr) = tm
	*(**time.Time)(ptr) = (*time.Time)(newPtr)
}

type errCodec struct {
	err       error
	operation string
}

func (c *errCodec) IsEmpty(_ unsafe.Pointer) bool {
	return false
}
func (c *errCodec) Encode(_ unsafe.Pointer, stream *jsoniter.Stream) {
	stream.Error = c.err
}
func (c *errCodec) Decode(_ unsafe.Pointer, iter *jsoniter.Iterator) {
	iter.ReportError(c.operation, c.err.Error())
}

// OverrideEncoders returns an extension that forces all time.Time values to be encoded using `enc`
func OverrideEncoders(enc TimeEncoder) jsoniter.Extension {
	return &extOverrideEncoders{
		enc: enc,
	}
}

type extOverrideEncoders struct {
	jsoniter.DummyExtension
	enc TimeEncoder
}

func (ext *extOverrideEncoders) CreateEncoder(typ reflect2.Type) jsoniter.ValEncoder {
	if typ := typ.Type1(); typ == typTime {
		return NewTimeEncoder(ext.enc, typ)
	}
	return nil
}

func (ext *extOverrideEncoders) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		typ2 := binding.Field.Type()
		enc := NewTimeEncoder(ext.enc, typ2.Type1())
		if enc == nil {
			continue
		}

		if e, ok := binding.Encoder.(EncoderDecorator); ok {
			enc = e.DecorateEncoder(typ2, enc)
		}

		binding.Encoder = enc
	}
}
