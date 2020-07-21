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
	codecs   Registry
	override fnCodec
	loc      *time.Location
	tagName  string
}

func NewExtension(options ...Option) *Extension {
	ext := Extension{}
	options = append([]Option{defaultRegistry}, options...)
	for _, option := range options {
		if option == nil {
			continue
		}
		option.apply(&ext)
	}
	return &ext
}

func (ext *Extension) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	tagName := ext.TagName()
	typTime := reflect.TypeOf(time.Time{})
	for _, binding := range desc.Fields {
		field := binding.Field
		// NOTE [tcodec]: Add support for *time.Time values
		if field.Type().Type1() != typTime {
			// We only modify decoders for `time.Time` fields.
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
		if decoder := ext.newValDecoder(codec); decoder != nil {
			// We only modify the underlying decoder if we resolved a decoder
			binding.Decoder = decoder
		}
		if encoder := ext.newValEncoder(codec); encoder != nil {
			// We only modify the underlying encoder if we resolved an encoder
			binding.Encoder = encoder
		}
	}
}

func (ext *Extension) TagName() string {
	if tagName := ext.tagName; tagName != "" {
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

func (ext *Extension) newValEncoder(codec TimeCodec) jsoniter.ValEncoder {
	encode := ext.override.encode
	if encode == nil {
		if codec == nil {
			return nil
		}
		encode = codec.EncodeTime
	}
	if loc := ext.loc; loc != nil {
		encode = EncodeIn(loc, encode).EncodeTime
	}
	return &jsonTimeEncoder{
		encode: encode,
	}
}
func (ext *Extension) newValDecoder(codec TimeCodec) jsoniter.ValDecoder {
	decode := ext.override.decode
	if decode == nil {
		if codec == nil {
			return nil
		}
		decode = codec.DecodeTime
	}
	if loc := ext.loc; loc != nil {
		decode = DecodeIn(loc, decode).DecodeTime
	}
	return &jsonTimeDecoder{
		decode: decode,
	}
}

func NewJSONDecoder(decoder TimeDecoder) jsoniter.ValDecoder {
	return &jsonTimeDecoder{
		decode: decoder.DecodeTime,
	}
}

type jsonTimeDecoder struct {
	decode TimeDecoderFunc
}

func (dec *jsonTimeDecoder) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	*((*time.Time)(ptr)) = dec.decode(iter)
}
