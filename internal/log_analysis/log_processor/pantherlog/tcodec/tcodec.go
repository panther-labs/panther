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
	"time"

	"github.com/itchyny/timefmt-go"
	jsoniter "github.com/json-iterator/go"
)

// TimeCodec can decode/encode time.Time values using jsoniter.
type TimeCodec interface {
	TimeEncoder
	TimeDecoder
}

// TimeDecoder can decode time.Time values from a jsoniter.Iterator.
type TimeDecoder interface {
	DecodeTime(iter *jsoniter.Iterator) time.Time
}

// TimeDecoderFunc is a helper to easily define TimeDecoder values.
type TimeDecoderFunc func(iter *jsoniter.Iterator) time.Time

var _ TimeDecoder = (TimeDecoderFunc)(nil)

func (fn TimeDecoderFunc) DecodeTime(iter *jsoniter.Iterator) time.Time {
	return fn(iter)
}

// TimeEncoder can encode time.Time values onto a jsoniter.Stream.
type TimeEncoder interface {
	EncodeTime(tm time.Time, stream *jsoniter.Stream)
}

// TimeEncoderFunc is a helper to easily define TimeEncoder values.
type TimeEncoderFunc func(tm time.Time, stream *jsoniter.Stream)

var _ TimeEncoder = (TimeEncoderFunc)(nil)

func (fn TimeEncoderFunc) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	fn(tm, stream)
}

// Split is a helper to split a TimeCodec into a decoder and an encoder.
func Split(codec TimeCodec) (TimeDecoder, TimeEncoder) {
	return resolveDecoder(codec), resolveEncoder(codec)
}

// Join is a helper to compose a TimeCodec from a decoder and an encoder.
func Join(decode TimeDecoder, encode TimeEncoder) TimeCodec {
	if c, ok := decode.(*joinCodec); ok {
		decode = c.decode
	}
	if c, ok := encode.(*joinCodec); ok {
		encode = c.encode
	}
	return &joinCodec{
		encode: resolveEncoder(encode),
		decode: resolveDecoder(decode),
	}
}

func resolveEncoder(enc TimeEncoder) TimeEncoder {
	if enc == nil {
		return nil
	}
	if join, ok := enc.(*joinCodec); ok {
		return join.encode
	}
	return enc
}

func resolveDecoder(dec TimeDecoder) TimeDecoder {
	if dec == nil {
		return nil
	}
	if join, ok := dec.(*joinCodec); ok {
		return join.decode
	}
	return dec
}

type joinCodec struct {
	encode TimeEncoder
	decode TimeDecoder
}

func (codec *joinCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	codec.encode.EncodeTime(tm, stream)
}
func (codec *joinCodec) DecodeTime(iter *jsoniter.Iterator) time.Time {
	return codec.decode.DecodeTime(iter)
}

// LayoutCodec uses a time layout to decode/encode a timestamp from a JSON value.
func LayoutCodec(layout string) TimeCodec {
	return layoutCodec(layout)
}

type layoutCodec string

func (layout layoutCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	stream.WriteString(tm.Format(string(layout)))
}

func (layout layoutCodec) DecodeTime(iter *jsoniter.Iterator) time.Time {
	switch iter.WhatIsNext() {
	case jsoniter.StringValue:
		s := iter.ReadString()
		if s == "" {
			return time.Time{}
		}
		tm, err := time.Parse(string(layout), s)
		if err != nil {
			iter.ReportError(`DecodeTime`, err.Error())
		}
		return tm
	case jsoniter.NilValue:
		iter.ReadNil()
		return time.Time{}
	default:
		iter.Skip()
		iter.ReportError(`DecodeTime`, `invalid JSON value`)
		return time.Time{}
	}
}

// StrftimeCodec uses strftime format to decode/encode a timestamp from a JSON string.
// https://strftime.org/
// https://linux.die.net/man/3/strftime
func StrftimeCodec(format string) TimeCodec {
	return strftimeCodec(format)
}

type strftimeCodec string

func (format strftimeCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	stream.WriteString(timefmt.Format(tm, string(format)))
}

func (format strftimeCodec) DecodeTime(iter *jsoniter.Iterator) time.Time {
	switch iter.WhatIsNext() {
	case jsoniter.StringValue:
		s := iter.ReadString()
		if s == "" {
			return time.Time{}
		}
		tm, err := timefmt.Parse(s, string(format))
		if err != nil {
			iter.ReportError(`DecodeTime`, err.Error())
		}
		return tm
	case jsoniter.NilValue:
		iter.ReadNil()
		return time.Time{}
	default:
		iter.Skip()
		iter.ReportError(`DecodeTime`, `invalid JSON value`)
		return time.Time{}
	}
}

// In forces a `time.Location` on all decoded/encoded timestamps
func In(loc *time.Location, codec TimeCodec) TimeCodec {
	return &joinCodec{
		encode: EncodeIn(loc, codec),
		decode: DecodeIn(loc, codec),
	}
}

// EncodeIn forces a `time.Location` on all encoded timestamps
func EncodeIn(loc *time.Location, enc TimeEncoder) TimeEncoder {
	enc = resolveEncoder(enc)
	if unwrap, ok := enc.(*locEncoder); ok {
		enc = resolveEncoder(unwrap.encode)
	}
	return &locEncoder{
		encode: resolveEncoder(enc),
		loc:    loc,
	}
}

type locEncoder struct {
	encode TimeEncoder
	loc    *time.Location
}

func (e *locEncoder) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	e.encode.EncodeTime(tm.In(e.loc), stream)
}

// DecodeIn forces a `time.Location` on all decoded timestamps
func DecodeIn(loc *time.Location, dec TimeDecoder) TimeDecoder {
	dec = resolveDecoder(dec)
	if unwrap, ok := dec.(*locDecoder); ok {
		dec = resolveDecoder(unwrap.decode)
	}
	return &locDecoder{
		decode: dec,
		loc:    loc,
	}
}

type locDecoder struct {
	decode TimeDecoder
	loc    *time.Location
}

func (d *locDecoder) DecodeTime(iter *jsoniter.Iterator) time.Time {
	return d.decode.DecodeTime(iter).In(d.loc)
}

func NewTimeEncoder(enc TimeEncoder, typ reflect.Type) jsoniter.ValEncoder {
	if enc == nil {
		enc = StdCodec()
	}
	switch typ {
	case typTime:
		return &jsonTimeEncoder{
			encode: enc.EncodeTime,
		}
	case typTimePtr:
		return &jsonTimePtrEncoder{
			encode: enc.EncodeTime,
		}
	default:
		return nil
	}
}

func NewTimeDecoder(dec TimeDecoder, typ reflect.Type) jsoniter.ValDecoder {
	if dec == nil {
		dec = StdCodec()
	}
	switch typ {
	case typTime:
		return &jsonTimeDecoder{
			decode: dec.DecodeTime,
		}
	case typTimePtr:
		return &jsonTimePtrDecoder{
			decode: dec.DecodeTime,
			typ:    typ.Elem(),
		}
	default:
		return nil
	}
}

// StdCodec behaves like the default UnmarshalJSON/MarshalJSON for time.Time values.
// The tcodec extension uses this TimeCodec when no `tcodec` tag is present on a field of type time.Time and
// the extension has no Config.DefaultCodec defined.
func StdCodec() TimeCodec {
	return &stdCodec{}
}

type stdCodec struct{}

func (*stdCodec) DecodeTime(iter *jsoniter.Iterator) time.Time {
	ts := iter.ReadString()
	tm, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		iter.ReportError(`DecodeTime`, err.Error())
	}
	return tm
}

const layoutRFC3339NanoJSON = `"` + time.RFC3339Nano + `"`

func (*stdCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	buf := stream.Buffer()
	buf = tm.AppendFormat(buf, layoutRFC3339NanoJSON)
	stream.SetBuffer(buf)
}

// TryDecoders returns a TimeDecoder that tries to decode a time.Time using `dec` and then each of the `fallback` decoders in order.
func TryDecoders(dec TimeDecoder, fallback ...TimeDecoder) TimeDecoder {
	return &tryDecoder{
		decoders: append([]TimeDecoder{dec}, fallback...),
	}
}

type tryDecoder struct {
	decoders []TimeDecoder
}

func (d *tryDecoder) DecodeTime(iter *jsoniter.Iterator) time.Time {
	rawJSON := iter.SkipAndReturnBytes()
	child := iter.Pool().BorrowIterator(rawJSON)
	for i, dec := range d.decoders {
		if i != 0 {
			child.ResetBytes(rawJSON)
			child.Error = nil
		}
		tm := dec.DecodeTime(child)
		if child.Error == nil {
			child.Pool().ReturnIterator(child)
			return tm
		}
	}
	iter.Error = child.Error
	child.Pool().ReturnIterator(child)
	return time.Time{}
}

type Time = time.Time

func init() {
	jsoniter.RegisterExtension(&Extension{})
}
