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

func TestNewExtension(t *testing.T) {
	type T struct {
		TimeRFC3339 time.Time `json:"t_rfc,omitempty" tcodec:"rfc3339"`
		TimeUnixMS  time.Time `json:"t_unix_ms,omitempty" tcodec:"unix_ms"`
		TimeUnix    time.Time `json:"t_unix,omitempty" tcodec:"unix"`
		TimeCustom  time.Time `json:"t_custom,omitempty" tcodec:"layout=2006-01-02"`
	}
	ext := NewExtension(Config{
		OverrideEncoder: EncodeIn(time.UTC, LayoutCodec(time.RFC3339Nano)),
	})
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(ext)

	tm := time.Date(2020, 10, 1, 14, 32, 54, 569*int(time.Millisecond), time.UTC)
	input := fmt.Sprintf(`{
		"t_rfc": "%s",
		"t_custom": "%s",
		"t_unix": "%f",
		"t_unix_ms": "%d"
	}`,
		tm.Format(time.RFC3339Nano),
		tm.Format("2006-01-02"),
		time.Duration(tm.UnixNano()).Seconds(),
		time.Duration(tm.UnixNano()).Milliseconds(),
	)
	actual := T{}
	err := api.UnmarshalFromString(input, &actual)
	require.NoError(t, err)
	expect := tm.Format(time.RFC3339Nano)
	require.Equal(t, tm.Format("2006-01-02"), actual.TimeCustom.UTC().Format("2006-01-02"), "custom")
	require.Equal(t, expect, actual.TimeRFC3339.UTC().Format(time.RFC3339Nano), "rfc3339")
	require.Equal(t, expect, actual.TimeUnix.UTC().Format(time.RFC3339Nano), "unix")
	require.Equal(t, expect, actual.TimeUnixMS.UTC().Format(time.RFC3339Nano), "unix_ms")

	{
		actual, err := api.MarshalToString(T{})
		require.NoError(t, err)
		require.Equal(t, `{}`, actual)
	}
	{
		loc, _ := time.LoadLocation("Europe/Athens")
		expect := time.Date(2020, 7, 3, 15, 12, 45, 0, loc)
		actual, err := api.MarshalToString(T{
			TimeRFC3339: expect,
		})
		require.NoError(t, err)
		require.Equal(t, `{"t_rfc":"2020-07-03T12:12:45Z"}`, actual)
	}
}

func TestConfig(t *testing.T) {
	{
		var ext Extension
		require.Equal(t, DefaultTagName, ext.TagName())
	}
	{
		ext := NewExtension(Config{})
		require.Equal(t, DefaultTagName, ext.TagName())
	}
	{
		ext := NewExtension(Config{
			OverrideEncoder: LayoutCodec(time.RFC3339Nano),
		})
		require.NotNil(t, ext.timeEncoderFunc(nil))
		require.Nil(t, ext.timeDecoderFunc(nil))
	}
	{
		ext := NewExtension(Config{
			OverrideDecoder: LayoutCodec(time.RFC3339Nano),
		})
		require.NotNil(t, ext.timeDecoderFunc(nil))
		require.Nil(t, ext.timeEncoderFunc(nil))
		require.Equal(t, DefaultTagName, ext.TagName())
	}
	{
		ext := NewExtension(Config{
			TagName: "foo",
		})
		require.Equal(t, "foo", ext.TagName())
		type T struct {
			Time time.Time `json:"tm" foo:"rfc3339"`
		}
		v := T{}
		api := jsoniter.Config{}.Froze()
		api.RegisterExtension(ext)
		require.NoError(t, api.UnmarshalFromString(`{"tm":"2006-01-02T15:04:05.999Z"}`, &v))
		expect := time.Date(2006, 1, 2, 15, 4, 5, 999*int(time.Millisecond), time.UTC)
		require.Equal(t, expect.Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano))
	}
	{
		loc, err := time.LoadLocation("Europe/Athens")
		require.NoError(t, err)
		ext := NewExtension(Config{
			Location: loc,
		})
		type T struct {
			Time time.Time `json:"tm" tcodec:"rfc3339"`
			Foo  string
		}
		v := T{}
		api := jsoniter.Config{}.Froze()
		api.RegisterExtension(ext)
		require.NoError(t, api.UnmarshalFromString(`{"tm":"2006-01-02T15:04:05.999Z"}`, &v))
		require.Equal(t, loc, v.Time.Location())
	}
	{
		ext := NewExtension(Config{
			DefaultCodec: UnixSecondsCodec(),
		})
		type T struct {
			Time time.Time `json:"tm"`
			Foo  string
		}
		v := T{}
		api := jsoniter.Config{}.Froze()
		api.RegisterExtension(ext)
		require.NoError(t, api.UnmarshalFromString(`{"tm":"1595257966.369"}`, &v))
		expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
		require.Equal(t, expect.Local().Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano))
	}
}

func TestPointerZeroValues(t *testing.T) {
	ext := NewExtension(Config{
		DefaultCodec: UnixSecondsCodec(),
	})
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(ext)
	type T struct {
		Time *time.Time `json:"tm,omitempty"`
	}
	now := time.Now()
	{
		v := T{
			Time: &now,
		}
		require.NoError(t, api.UnmarshalFromString(`{"tm":""}`, &v))
		require.Nil(t, v.Time)
	}
	{
		v := T{}
		require.NoError(t, api.UnmarshalFromString(`{"tm":""}`, &v))
		require.Nil(t, v.Time)
	}
	{
		v := T{}
		require.NoError(t, api.UnmarshalFromString(`{"tm":"1595257966.369"}`, &v))
		expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
		require.Equal(t, expect.Local().Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano))
	}
	{
		v := T{
			Time: &now,
		}
		require.NoError(t, api.UnmarshalFromString(`{"tm":"1595257966.369"}`, &v))
		expect := time.Date(2020, 7, 20, 15, 12, 46, int(0.369*float64(time.Second.Nanoseconds())), time.UTC)
		require.Equal(t, expect.Local().Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano))
	}
	{
		actual, err := api.MarshalToString(T{
			Time: &now,
		})
		require.NoError(t, err)
		require.Equal(t, `{"tm":1595257966.369}`, actual)
	}
	{
		actual, err := api.MarshalToString(T{})
		require.NoError(t, err)
		require.Equal(t, `{}`, actual)
	}
	{
		type T struct {
			Time time.Time `json:"tm"`
		}
		actual, err := api.MarshalToString(T{})
		require.NoError(t, err)
		require.Equal(t, `{"tm":null}`, actual)
	}
	{
		type T struct {
			Time *time.Time `json:"tm"`
		}
		actual, err := api.MarshalToString(T{})
		require.NoError(t, err)
		require.Equal(t, `{"tm":null}`, actual)
	}
}
