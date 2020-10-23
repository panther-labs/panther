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
	"io"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestUnixMilliseconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259*time.Millisecond.Nanoseconds()), time.UTC).Local()
	actual := UnixMilliseconds(1590364207259)
	require.Equal(t, expect.Format(time.RFC3339Nano), actual.Format(time.RFC3339Nano))
	require.Equal(t, expect, actual)
}
func TestUnixMicroseconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259123*time.Microsecond.Nanoseconds()), time.UTC).Local()
	actual := UnixMicroseconds(1590364207259123)
	require.Equal(t, expect.Format(time.RFC3339Nano), actual.Format(time.RFC3339Nano))
	require.Equal(t, expect, actual)
}
func TestUnixNanoseconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259123456), time.UTC).Local()
	actual := UnixNanoseconds(1590364207259123456)
	require.Equal(t, expect.Format(time.RFC3339Nano), actual.Format(time.RFC3339Nano))
	require.Equal(t, expect, actual)
}
func TestUnixSeconds(t *testing.T) {
	expect := time.Date(2020, 05, 24, 23, 50, 07, int(259*time.Millisecond.Nanoseconds()), time.UTC).Local()
	actual := UnixSeconds(1590364207.259)
	require.Equal(t, expect.Format(time.RFC3339Nano), actual.Format(time.RFC3339Nano))
	require.Equal(t, expect, actual)
}

func TestGlobalRegister(t *testing.T) {
	require.NoError(t, Register("foo", LayoutCodec("2006")))
	require.Error(t, Register("bar", nil))
	require.Error(t, Register("foo", LayoutCodec("2006")))
	require.Panics(t, func() {
		MustRegister("foo", nil)
	})
	require.Nil(t, Lookup("baz"))
	require.NotNil(t, Lookup("foo"))

	type T struct {
		Time time.Time `json:"time" tcodec:"foo"`
		Unix time.Time `json:"unix" tcodec:"unix"`
	}
	v := T{}
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(&Extension{})
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
	dec := UnixMillisecondsCodec()
	iter := jsoniter.Parse(jsoniter.ConfigDefault, nil, 1024)
	iter.ResetBytes([]byte(`""`))
	iter.Error = nil
	tm := dec.DecodeTime(iter)
	require.NoError(t, iter.Error)
	require.Equal(t, time.Time{}.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`"0"`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.NoError(t, iter.Error)
	require.Equal(t, time.Unix(0, 0).Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`0`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.NoError(t, iter.Error)
	require.Equal(t, time.Unix(0, 0).Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`foo`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.Error(t, iter.Error)

	iter.ResetBytes([]byte(`"1595257966369"`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
	require.Equal(t, expect.Format(time.RFC3339Nano), tm.UTC().Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`1595257966369`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.Equal(t, io.EOF, iter.Error)
	require.Equal(t, expect.Format(time.RFC3339Nano), tm.UTC().Format(time.RFC3339Nano))
}

func TestUnixSecondsDecoder(t *testing.T) {
	dec := UnixSecondsCodec()
	iter := jsoniter.Parse(jsoniter.ConfigDefault, nil, 1024)

	iter.ResetBytes([]byte(`""`))
	iter.Error = nil
	tm := dec.DecodeTime(iter)
	require.NoError(t, iter.Error)
	require.Equal(t, time.Time{}.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`null`))
	tm = dec.DecodeTime(iter)
	require.NoError(t, iter.Error)
	require.Equal(t, time.Time{}.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`0`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.Equal(t, io.EOF, iter.Error)
	require.Equal(t, time.Unix(0, 0).Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	str := ""
	err := jsoniter.UnmarshalFromString(`"0"`, &str)
	require.NoError(t, err)
	require.Equal(t, "0", str)
	iter.ResetBytes([]byte(`"0"`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.NoError(t, iter.Error)
	require.Equal(t, time.Unix(0, 0).Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`"foo"`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.Error(t, iter.Error)

	iter.ResetBytes([]byte(`"1595257966.369"`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.NoError(t, iter.Error)
	expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
	require.Equal(t, expect.Format(time.RFC3339Nano), tm.UTC().Format(time.RFC3339Nano))

	iter.ResetBytes([]byte(`1595257966.369`))
	iter.Error = nil
	tm = dec.DecodeTime(iter)
	require.Equal(t, io.EOF, iter.Error)
	require.Equal(t, expect.Format(time.RFC3339Nano), tm.UTC().Format(time.RFC3339Nano))
}

func TestPointers(t *testing.T) {
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(&Extension{})
	type T struct {
		Time *time.Time `json:"tm,omitempty" tcodec:"unix"`
	}
	v := T{}
	err := api.UnmarshalFromString(`{
		"tm": "1595257966.369"
	}`, &v)

	expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC).Local()
	require.NoError(t, err)
	require.NotNil(t, v.Time)
	require.Equal(t, expect.Local().Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano))
}

func TestTryDecoder_DecodeTime(t *testing.T) {
	dec := LayoutCodec(time.RFC3339).(TimeDecoder)
	dec = TryDecoders(dec, LayoutCodec(time.ANSIC))
	expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
	{
		input := fmt.Sprintf(`"%s"`, expect.Format(time.RFC3339Nano))
		iter := jsoniter.ParseString(jsoniter.ConfigDefault, input)
		actual := dec.DecodeTime(iter)
		require.NoError(t, iter.Error)
		require.Equal(t, expect.Format(time.RFC3339Nano), actual.Format(time.RFC3339Nano))
	}
	{
		input := fmt.Sprintf(`"%s"`, expect.Format(time.ANSIC))
		iter := jsoniter.ParseString(jsoniter.ConfigDefault, input)
		actual := dec.DecodeTime(iter)
		require.NoError(t, iter.Error)
		// ANSIC has seconds precision
		require.Equal(t, expect.Format(time.RFC3339), actual.Format(time.RFC3339))
	}
	{
		input := fmt.Sprintf(`"%s"`, expect.Format(time.RubyDate))
		iter := jsoniter.ParseString(jsoniter.ConfigDefault, input)
		_ = dec.DecodeTime(iter)
		require.Error(t, iter.Error)
	}
}
