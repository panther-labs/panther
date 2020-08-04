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
	config Config
}

// DefaultTagName is the struct tag name used for defining time decoders for a time.Time field.
const DefaultTagName = "tcodec"

type Config struct {
	// Codecs overrides the TimeCodec registry to use for resolving TimeCodecs.
	// If this option is `nil` the default registry is used.
	Codecs *Registry
	// DefaultCodec sets the default codec to use when a tag is not found or cannot be resolved to a TimeCodec.
	// If this option is `nil` fields with unresolved codecs will not be modified by the extension.
	DefaultCodec TimeCodec
	// TagName sets the struct tag name to use for tcodec options.
	// If this option is not set the `DefaultTagName` will be used.
	TagName string
	// DecorateEncoder enforces all timestamps to be encoded using this TimeEncoder.
	// If this option is `nil` timestamps will be encoded using their individual TimeCodec.
	DecorateCodec func(TimeCodec) TimeCodec
}

func NewExtension(config Config) *Extension {
	if config.Codecs == nil {
		config.Codecs = defaultRegistry
	}
	return &Extension{
		config: config,
	}
}

var typTime = reflect.TypeOf(time.Time{})

func (ext *Extension) CreateEncoder(typ reflect2.Type) jsoniter.ValEncoder {
	typ1 := typ.Type1()
	if !typ1.ConvertibleTo(typTime) {
		return nil
	}
	_, enc := ext.split(nil)
	if enc == nil {
		return nil
	}
	return NewTimeEncoder(enc, typ1)
}
func (ext *Extension) CreateDecoder(typ reflect2.Type) jsoniter.ValDecoder {
	typ1 := typ.Type1()
	if !typ1.ConvertibleTo(typTime) {
		return nil
	}
	dec, _ := ext.split(nil)
	if dec == nil {
		return nil
	}
	return NewTimeDecoder(dec, typ1)
}

func (ext *Extension) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	tagName := ext.TagName()
	for _, binding := range desc.Fields {
		field := binding.Field
		typ := field.Type().Type1()
		if !isTimeType(typ) {
			continue
		}

		// NOTE: [tcodec] Add support for other layout types such as strftime (https://strftime.org/)
		var codec TimeCodec
		if tag, ok := field.Tag().Lookup(tagName); ok {
			if strings.HasPrefix(tag, "layout=") {
				// The tag is of the form `layout=GO_TIME_LAYOUT`.
				// We strip the prefix and use a LayoutCodec.
				layout := strings.TrimPrefix(tag, "layout=")
				codec = LayoutCodec(layout)
			} else {
				// The tag is a registered decoder name
				codec = Lookup(tag)
			}
		}
		dec, enc := ext.split(codec)
		if dec != nil {
			// We only modify the underlying decoder if we resolved a decoder
			binding.Decoder = NewTimeDecoder(dec, typ)
		}
		if enc != nil {
			// We only modify the underlying encoder if we resolved an encoder
			valEncoder := NewTimeEncoder(enc, typ)
			// Reserve decorations.
			// This is needed so globally registered extensions can apply their decorations on top of tcodec ones
			type decorator interface {
				DecorateEncoder(typ reflect2.Type, enc jsoniter.ValEncoder) jsoniter.ValEncoder
			}
			if d, ok := binding.Encoder.(decorator); ok {
				valEncoder = d.DecorateEncoder(field.Type(), valEncoder)
			}
			binding.Encoder = valEncoder
		}
	}
}

func isTimeType(typ reflect.Type) bool {
	switch {
	case typ.ConvertibleTo(typTime):
		// Type is time.Time
		return true
	case isEmbeddedTime(typ):
		// Type is struct { time.Time }
		return true
	case typ.Kind() == reflect.Ptr && typ.Elem().ConvertibleTo(typTime):
		// Type is *time.Time
		return true
	case typ.Kind() == reflect.Ptr && isEmbeddedTime(typ.Elem()):
		// Type is *struct { time.Time }
		return true
	default:
		// We only modify encoders/decoders for the above types
		return false
	}
}

// check if type is a struct wrapping time.Time
// ```
// type T struct {
//   time.Time
// }
// ```
func isEmbeddedTime(typ reflect.Type) bool {
	if typ.Kind() == reflect.Struct && typ.NumField() == 1 {
		if field := typ.Field(0); field.Anonymous && field.Type.ConvertibleTo(typTime) {
			return true
		}
	}
	return false
}

func (ext *Extension) TagName() string {
	if tagName := ext.config.TagName; tagName != "" {
		return tagName
	}
	return DefaultTagName
}

func (ext *Extension) split(codec TimeCodec) (decoder TimeDecoder, encoder TimeEncoder) {
	if codec == nil {
		codec = ext.config.DefaultCodec
	}
	if decorate := ext.config.DecorateCodec; decorate != nil {
		codec = decorate(codec)
	}
	return Split(codec)
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
	if tm == nil {
		enc.encode(time.Time{}, stream)
	} else {
		enc.encode(*tm, stream)
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
