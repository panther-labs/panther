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

func TestNewTimeDecoderExtension(t *testing.T) {
	type T struct {
		TimeRFC3339 time.Time `json:"t_rfc" tcodec:"rfc3339"`
		TimeUnixMS  time.Time `json:"t_unix_ms" tcodec:"unix_ms"`
		TimeUnix    time.Time `json:"t_unix" tcodec:"unix"`
		TimeCustom  time.Time `json:"t_custom" tcodec:"layout=2006-01-02"`
	}
	ext := NewDecoderExtension()
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
}
