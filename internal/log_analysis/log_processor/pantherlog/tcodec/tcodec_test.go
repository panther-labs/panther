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
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestUnixMilliseconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259*time.Millisecond.Nanoseconds()), time.UTC)
	actual := UnixMilliseconds(1590364207259)
	require.Equal(t, expect, actual.UTC())
}
func TestUnixSeconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259*time.Millisecond.Nanoseconds()), time.UTC)
	actual := UnixSeconds(1590364207.259)
	require.Equal(t, expect, actual.UTC())
}

func TestRegisterDecoder(t *testing.T) {
	require.NoError(t, RegisterDecoder("foo", LayoutDecoder("2006")))
	require.Error(t, RegisterDecoder("bar", nil))
	require.Error(t, RegisterDecoder("foo", LayoutDecoder("2006")))
	require.Panics(t, func() {
		MustRegisterDecoder("foo", nil)
	})
	require.Nil(t, LookupDecoder("baz"))
	require.NotNil(t, LookupDecoder("foo"))

	type T struct {
		Time time.Time `json:"time" tcodec:"foo"`
		Unix time.Time `json:"unix" tcodec:"unix"`
	}
	v := T{}
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(NewDecoderExtension())
	require.NoError(t, api.UnmarshalFromString(`{"time":"2020"}`, &v))
	expect := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	require.Equal(t, expect, v.Time.UTC())
	v = T{}
	require.Error(t, api.UnmarshalFromString(`{"time":"abc"}`, &v))
	v = T{}
	require.Error(t, api.UnmarshalFromString(`{"time":123abc}`, &v))
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{"time":null}`, &v))
	require.Equal(t, time.Time{}, v.Time)
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{}`, &v))
	require.Equal(t, time.Time{}, v.Time)
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{"unix":null}`, &v))
	require.Equal(t, time.Time{}, v.Time)
	v = T{}
	require.NoError(t, api.UnmarshalFromString(`{"unix":""}`, &v))
	require.Equal(t, time.Time{}, v.Unix)

	v = T{}
	expect = time.Date(2020, 2, 4, 13, 20, 24, 123456789*int(time.Microsecond), time.UTC)
	unix := expect.UnixNano()
	unixSeconds := time.Duration(unix).Seconds()
	input := fmt.Sprintf(`{"unix":%f}`, unixSeconds)
	require.NoError(t, api.UnmarshalFromString(input, &v))
	require.Equal(t, expect.Format(time.RFC3339Nano), v.Unix.UTC().Format(time.RFC3339Nano))

	v = T{}
	input = fmt.Sprintf(`{"unix":"%f"}`, unixSeconds)
	require.NoError(t, api.UnmarshalFromString(input, &v))
	require.Equal(t, expect.Format(time.RFC3339Nano), v.Unix.UTC().Format(time.RFC3339Nano))

	require.Error(t, api.UnmarshalFromString(`{"unix":{}}`, &v))
	require.Error(t, api.UnmarshalFromString(`{"unix":[]}`, &v))
	require.Error(t, api.UnmarshalFromString(`{"unix":true}`, &v))
}

func TestUnixMillisecondsDecoder(t *testing.T) {
	dec := UnixMillisecondsDecoder()
	tm, err := dec.DecodeTime("")
	require.NoError(t, err)
	require.Equal(t, time.Time{}.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	tm, err = dec.DecodeTime("0")
	require.NoError(t, err)
	require.Equal(t, time.Unix(0, 0).Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	tm, err = dec.DecodeTime("foo")
	require.Error(t, err)

	tm, err = dec.DecodeTime("1595257966369")
	require.NoError(t, err)
	expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
	require.Equal(t, expect.Format(time.RFC3339Nano), tm.UTC().Format(time.RFC3339Nano))
}

func TestUnixSecondsDecoder(t *testing.T) {
	dec := UnixSecondsDecoder()
	tm, err := dec.DecodeTime("")
	require.NoError(t, err)
	require.Equal(t, time.Time{}.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	tm, err = dec.DecodeTime("0")
	require.NoError(t, err)
	require.Equal(t, time.Unix(0, 0).Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	tm, err = dec.DecodeTime("foo")
	require.Error(t, err)

	tm, err = dec.DecodeTime("1595257966.369")
	require.NoError(t, err)
	expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
	require.Equal(t, expect.Format(time.RFC3339Nano), tm.UTC().Format(time.RFC3339Nano))
}
