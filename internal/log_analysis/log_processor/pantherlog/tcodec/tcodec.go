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
	"errors"
	"strconv"
	"time"
)

var (
	registeredDecoders = map[string]TimeDecoder{
		"unix":    UnixSecondsDecoder(),
		"unix_ms": UnixMillisecondsDecoder(),
		"rfc3339": LayoutDecoder(time.RFC3339Nano),
	}
)

type TimeDecoder interface {
	DecodeTime(input string) (time.Time, error)
}

type TimeDecoderFunc func(input string) (time.Time, error)

var _ TimeDecoder = (TimeDecoderFunc)(nil)

func (fn TimeDecoderFunc) DecodeTime(input string) (time.Time, error) {
	return fn(input)
}

func RegisterDecoder(name string, decoder TimeDecoder) error {
	if decoder == nil {
		return errors.New("nil decoder")
	}
	if name == "" {
		return errors.New("anonymous time decoder")
	}
	if _, duplicate := registeredDecoders[name]; duplicate {
		return errors.New("duplicate time decoder " + name)
	}
	registeredDecoders[name] = decoder
	return nil
}

func MustRegisterDecoder(name string, decoder TimeDecoder) {
	if err := RegisterDecoder(name, decoder); err != nil {
		panic(err)
	}
}

func LookupDecoder(name string) TimeDecoder {
	return registeredDecoders[name]
}

func UnixSeconds(sec float64) time.Time {
	// We lose nanosecond precision to microsecond to have stable results with float64 values.
	const usec = float64(time.Second / time.Microsecond)
	const precision = int64(time.Microsecond)
	return time.Unix(0, int64(sec*usec)*precision)
}

func UnixSecondsDecoder() TimeDecoder {
	return &unixSecondsDecoder{}
}

type unixSecondsDecoder struct{}

func (*unixSecondsDecoder) DecodeTime(input string) (tm time.Time, err error) {
	if input == "" {
		return
	}
	f, err := strconv.ParseFloat(input, 64)
	if err != nil {
		return
	}
	return UnixSeconds(f), nil
}

func UnixMillisecondsDecoder() TimeDecoder {
	return &unixMillisecondsDecoder{}
}

func UnixMilliseconds(n int64) time.Time {
	return time.Unix(0, n*int64(time.Millisecond))
}

type unixMillisecondsDecoder struct{}

func (*unixMillisecondsDecoder) DecodeTime(input string) (tm time.Time, err error) {
	if input == "" {
		return
	}
	n, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return
	}
	return UnixMilliseconds(n), nil
}

func LayoutDecoder(layout string) TimeDecoder {
	return layoutDecoder(layout)
}

type layoutDecoder string

func (layout layoutDecoder) DecodeTime(input string) (time.Time, error) {
	return time.Parse(string(layout), input)
}
