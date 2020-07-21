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
	jsoniter "github.com/json-iterator/go"
	"strconv"
	"time"
)

type TimeCodec interface {
	TimeEncoder
	TimeDecoder
}

type TimeDecoder interface {
	DecodeTime(iter *jsoniter.Iterator) time.Time
}

type TimeDecoderFunc func(iter *jsoniter.Iterator) time.Time

var _ TimeDecoder = (TimeDecoderFunc)(nil)

func (fn TimeDecoderFunc) DecodeTime(iter *jsoniter.Iterator) time.Time {
	return fn(iter)
}

type TimeEncoder interface {
	EncodeTime(tm time.Time, stream *jsoniter.Stream)
}

type TimeEncoderFunc func(tm time.Time, stream *jsoniter.Stream)

var _ TimeEncoder = (TimeEncoderFunc)(nil)

func (fn TimeEncoderFunc) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	fn(tm, stream)
}

func New(decode TimeDecoder, encode TimeEncoder) TimeCodec {
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

func NewFunc(decode TimeDecoderFunc, encode TimeEncoderFunc) TimeCodec {
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

func UnixSeconds(sec float64) time.Time {
	// We lose nanosecond precision to microsecond to have stable results with float64 values.
	const usec = float64(time.Second / time.Microsecond)
	const precision = int64(time.Microsecond)
	return time.Unix(0, int64(sec*usec)*precision)
}

func UnixSecondsCodec() TimeCodec {
	return &unixSecondsCodec{}
}

type unixSecondsCodec struct{}

func (*unixSecondsCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	unixSeconds := time.Duration(tm.UnixNano()).Seconds()
	const usecPrecision = int(time.Second / time.Microsecond)
	stream.WriteFloat64(unixSeconds)
}

func (*unixSecondsCodec) DecodeTime(iter *jsoniter.Iterator) (tm time.Time) {
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		return
	case jsoniter.NumberValue:
		f := iter.ReadFloat64()
		return UnixSeconds(f)
	case jsoniter.StringValue:
		s := iter.ReadString()
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

func UnixMilliseconds(n int64) time.Time {
	return time.Unix(0, n*int64(time.Millisecond))
}

func UnixMillisecondsCodec() TimeCodec {
	return &unixMillisecondsCodec{}
}

type unixMillisecondsCodec struct{}

func (*unixMillisecondsCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	msec := tm.UnixNano() / int64(time.Millisecond)
	stream.WriteInt64(msec)
}

func (*unixMillisecondsCodec) DecodeTime(iter *jsoniter.Iterator) (tm time.Time) {
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		return
	case jsoniter.NumberValue:
		msec := iter.ReadInt64()
		return UnixMilliseconds(msec)
	case jsoniter.StringValue:
		s := iter.ReadString()
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

func In(loc *time.Location, codec TimeCodec) TimeCodec {
	return &fnCodec{
		encode: EncodeIn(loc, TimeEncoderFunc(codec.EncodeTime)).EncodeTime,
		decode: DecodeIn(loc, TimeDecoderFunc(codec.DecodeTime)).DecodeTime,
	}
}
func UTC(codec TimeCodec) TimeCodec {
	return In(time.UTC, codec)
}
func DecodeUTC(decoder TimeDecoder) TimeDecoder {
	return DecodeIn(time.UTC, decoder)
}
func EncodeUTC(encoder TimeEncoder) TimeEncoder {
	return EncodeIn(time.UTC, encoder)
}
