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
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
)

// UnixSeconds reads a timestamp from seconds since UNIX epoch.
// Fractions of a second can be set using the fractional part of a float.
// Precision is kept up to microseconds to avoid float64 precision issues.
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
	return &unixCodec{
		Unit: time.Millisecond,
	}
}

// UnixMicroseconds reads a timestamp from microseconds since UNIX epoch.
// It decodes both string and number JSON values and encodes always to number.
func UnixMicroseconds(n int64) time.Time {
	return time.Unix(0, n*int64(time.Microsecond))
}

// UnixMicrosecondsCodec decodes/encodes a timestamps in UNIX millisecond epoch.
// It decodes both string and number JSON values and encodes always to number.
func UnixMicrosecondsCodec() TimeCodec {
	return &unixCodec{
		Unit: time.Microsecond,
	}
}

// UnixNanoseconds reads a timestamp from nanoseconds since UNIX epoch.
// It decodes both string and number JSON values and encodes always to number.
func UnixNanoseconds(n int64) time.Time {
	return time.Unix(0, n)
}

// UnixNanosecondsCodec decodes/encodes a timestamps in UNIX millisecond epoch.
// It decodes both string and number JSON values and encodes always to number.
func UnixNanosecondsCodec() TimeCodec {
	return &unixCodec{
		Unit: time.Nanosecond,
	}
}

type unixCodec struct {
	Unit time.Duration
}

func (c *unixCodec) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	if tm.IsZero() {
		stream.WriteNil()
		return
	}
	msec := tm.UnixNano() / int64(c.Unit)
	stream.WriteInt64(msec)
}

func (c *unixCodec) DecodeTime(iter *jsoniter.Iterator) (tm time.Time) {
	switch iter.WhatIsNext() {
	case jsoniter.NumberValue:
		n := iter.ReadInt64()
		return time.Unix(0, n*int64(c.Unit))
	case jsoniter.NilValue:
		iter.ReadNil()
		return
	case jsoniter.StringValue:
		s := iter.ReadString()
		if s == "" {
			return
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			iter.ReportError("ReadUnixTimestamp", err.Error())
			return
		}
		return time.Unix(0, n*int64(c.Unit))
	default:
		iter.Skip()
		iter.ReportError("ReadUnixTimestamp", `invalid JSON value`)
		return
	}
}
