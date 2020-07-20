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

// NewDecoderExtension creates a jsoniter.Extension that decodes JSON values to time.Time.
// The extension reaads `time` struct tags and matches to registered TimeDecoders.
// To decoder using a layout specific for a field use `layout=GO_TIME_LAYOUT` tag value.
func NewDecoderExtension() jsoniter.Extension {
	return &timeDecoderExt{}
}

type timeDecoderExt struct {
	jsoniter.DummyExtension
}

const TagName = "tcodec"

func (*timeDecoderExt) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	typTime := reflect.TypeOf(time.Time{})
	for _, binding := range desc.Fields {
		field := binding.Field
		tag, ok := field.Tag().Lookup(TagName)
		if !ok {
			continue
		}
		if field.Type().Type1() != typTime {
			continue
		}
		var decoder TimeDecoder
		if strings.HasPrefix(tag, "layout=") {
			layout := strings.TrimPrefix(tag, "layout=")
			decoder = TimeLayout(layout)
		} else if d, ok := registeredDecoders[tag]; ok {
			decoder = d
		}
		if decoder != nil {
			binding.Decoder = NewJSONDecoder(decoder)
		}
	}
}

func NewJSONDecoder(decoder TimeDecoder) jsoniter.ValDecoder {
	return &jsonDecoder{
		decoder: decoder,
	}
}

type jsonDecoder struct {
	decoder TimeDecoder
}

func (dec *jsonDecoder) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadTimestamp"
	switch iter.WhatIsNext() {
	case jsoniter.StringValue:
		s := iter.ReadString()
		tm, err := dec.decoder.DecodeTime(s)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*time.Time)(ptr)) = tm
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*time.Time)(ptr)) = time.Time{}
	case jsoniter.NumberValue:
		raw := iter.SkipAndReturnBytes()
		tm, err := dec.decoder.DecodeTime(string(raw))
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*time.Time)(ptr)) = tm
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid JSON value")
	}
}

// RegisterJSONEncoder registers an encoder override for all `time.Time` values as strings using a layout.
// If a location is provided all times are first converted to that location.
// Zero time values are considered empty and omitted when omitempty is set.
func RegisterJSONEncoder(api jsoniter.API, layout string, loc *time.Location) {
	var (
		typTime       = reflect2.TypeOf(time.Time{})
		layoutJSON, _ = api.MarshalToString(layout)
		ext           = jsoniter.EncoderExtension{
			typTime: &jsonEncoder{layout: layoutJSON, location: loc},
		}
	)
	api.RegisterExtension(ext)
}

type jsonEncoder struct {
	layout   string
	location *time.Location
}

func (*jsonEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	tm := (*time.Time)(ptr)
	return tm.IsZero()
}

func (enc *jsonEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	tm := (*time.Time)(ptr)
	if loc := enc.location; loc != nil {
		stream.SetBuffer(tm.In(loc).AppendFormat(stream.Buffer(), enc.layout))
		return
	}
	stream.SetBuffer(tm.AppendFormat(stream.Buffer(), enc.layout))
}
