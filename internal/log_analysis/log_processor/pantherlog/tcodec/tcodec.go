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
	"strconv"
	"time"

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
	return codec, codec
}

// Join is a helper to compose a TimeCodec from a decoder and an encoder.
func Join(decode TimeDecoder, encode TimeEncoder) TimeCodec {
	return &fnCodec{
		encode: resolveEncodeFunc(encode),
		decode: resolveDecodeFunc(decode),
	}
}

func resolveEncodeFunc(enc TimeEncoder) TimeEncoderFunc {
	if enc == nil {
		return nil
	}
	if fn, ok := enc.(TimeEncoderFunc); ok {
		return fn
	}
	return enc.EncodeTime
}

func resolveDecodeFunc(dec TimeDecoder) TimeDecoderFunc {
	if dec == nil {
		return nil
	}
	if fn, ok := dec.(TimeDecoderFunc); ok {
		return fn
	}
	return dec.DecodeTime
}

// Join is a helper to compose a TimeCodec from a decoder and an encoder function.
func JoinFunc(decode TimeDecoderFunc, encode TimeEncoderFunc) TimeCodec {
	return &fnCodec{
		encode: encode,
		decode: decode,
	}
}

type fnCodec struct {
	encode TimeEncoderFunc
	decode TimeDecoderFunc
}

func (codec *fnCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	codec.encode(tm, stream)
}
func (codec *fnCodec) DecodeTime(iter *jsoniter.Iterator) time.Time {
	return codec.decode(iter)
}

// UnixSeconds reads a timestamp from seconds since UNIX epoch.
// Fractions of a second can be set using the fractional part of a float.
// Precision is kept up to Microseconds to avoid float64 precision issues.
func UnixSeconds(sec float64) time.Time {
	// We lose nanosecond precision to microsecond to have stable results with float64 values.
	const usec = float64(time.Second / time.Microsecond)
	const precision = int64(time.Microsecond)
	return time.Unix(0, int64(sec*usec)*precision)
}

// UnixSecondsCodec decodes/encodes a timestamp from seconds since UNIX epoch.
// Fractions of a second can be set using the fractional part of a float.
// Precision is kept up to Microseconds to avoid float64 precision issues.
func UnixSecondsCodec() TimeCodec {
	return &unixSecondsCodec{}
}

type unixSecondsCodec struct{}

func (*unixSecondsCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	if tm.IsZero() {
		stream.WriteNil()
		return
	}
	tm = tm.Truncate(time.Microsecond)
	unixSeconds := time.Duration(tm.UnixNano()).Seconds()
	stream.WriteFloat64(unixSeconds)
}

func (*unixSecondsCodec) DecodeTime(iter *jsoniter.Iterator) (tm time.Time) {
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		f := iter.ReadFloat64()
		return UnixSeconds(f)
	case jsoniter.NilValue:
		iter.ReadNil()
		return
	case jsoniter.StringValue:
		s := iter.ReadString()
		if s == "" {
			return
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			iter.ReportError("ReadUnixSeconds", err.Error())
			return
		}
		return UnixSeconds(f)
	default:
		iter.Skip()
		iter.ReportError("ReadUnixSeconds", `invalid JSON value`)
		return
	}
}

// UnixMilliseconds reads a timestamp from milliseconds since UNIX epoch.
func UnixMilliseconds(n int64) time.Time {
	return time.Unix(0, n*int64(time.Millisecond))
}

// UnixMillisecondsCodec decodes/encodes a timestamps in UNIX millisecond epoch.
// It decodes both string and number JSON values and encodes always to number.
func UnixMillisecondsCodec() TimeCodec {
	return &unixMillisecondsCodec{}
}

type unixMillisecondsCodec struct{}

func (*unixMillisecondsCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	if tm.IsZero() {
		stream.WriteNil()
		return
	}
	msec := tm.UnixNano() / int64(time.Millisecond)
	stream.WriteInt64(msec)
}

func (*unixMillisecondsCodec) DecodeTime(iter *jsoniter.Iterator) (tm time.Time) {
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		msec := iter.ReadInt64()
		return UnixMilliseconds(msec)
	case jsoniter.NilValue:
		iter.ReadNil()
		return
	case jsoniter.StringValue:
		s := iter.ReadString()
		if s == "" {
			return
		}
		msec, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			iter.ReportError("ReadUnixMilliseconds", err.Error())
			return
		}
		return UnixMilliseconds(msec)
	default:
		iter.Skip()
		iter.ReportError("ReadUnixMilliseconds", `invalid JSON value`)
		return
	}
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
		tm, err := time.Parse(string(layout), iter.ReadString())
		if err != nil {
			iter.ReportError(`ParseTime`, err.Error())
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

// UTC forces UTC on all decoded/encoded timestamps
func UTC(codec TimeCodec) TimeCodec {
	return In(time.UTC, codec)
}

// In forces a `time.Location` on all decoded/encoded timestamps
func In(loc *time.Location, codec TimeCodec) TimeCodec {
	return &fnCodec{
		encode: EncodeIn(loc, TimeEncoderFunc(codec.EncodeTime)).EncodeTime,
		decode: DecodeIn(loc, TimeDecoderFunc(codec.DecodeTime)).DecodeTime,
	}
}

// DecodeUTC forces UTC on all decoded timestamps
func DecodeUTC(decoder TimeDecoder) TimeDecoder {
	return DecodeIn(time.UTC, decoder)
}

// EncodeUTC forces UTC on all encoded timestamps
func EncodeUTC(encoder TimeEncoder) TimeEncoder {
	return EncodeIn(time.UTC, encoder)
}

// EncodeIn forces a `time.Location` on all encoded timestamps
func EncodeIn(loc *time.Location, encoder TimeEncoder) TimeEncoder {
	return &locEncoder{
		encode: resolveEncodeFunc(encoder),
		loc:    loc,
	}
}

type locEncoder struct {
	encode TimeEncoderFunc
	loc    *time.Location
}

func (e *locEncoder) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	e.encode(tm.In(e.loc), stream)
}

// DecodeIn forces a `time.Location` on all decoded timestamps
func DecodeIn(loc *time.Location, decoder TimeDecoder) TimeDecoder {
	return &locDecoder{
		decode: resolveDecodeFunc(decoder),
		loc:    loc,
	}
}

type locDecoder struct {
	decode TimeDecoderFunc
	loc    *time.Location
}

func (d *locDecoder) DecodeTime(iter *jsoniter.Iterator) time.Time {
	return d.decode(iter).In(d.loc)
}

// ValidateEmbeddedTimeValue can be used by validator package to check values that embed time.Time
// ```
// type T struct {
//   time.Time
// }
//
// validate := validator.New()
// validate.RegisterCustomTypeFunc(tcodec.ValidateEmbeddedTimeValue, T{})
//
// type Foo struct {
//   Time T `validate:"required"`
// }
//
// err := validate.Struct(&Foo{}) // error should be non nil
// ```
func ValidateEmbeddedTimeValue(val reflect.Value) interface{} {
	tm := val.Field(0).Interface().(time.Time)
	if tm.IsZero() {
		return nil
	}
	return tm
}
