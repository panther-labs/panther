package timestamp

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
)

var (
	expectedString        = "2019-12-15 01:01:01 +0000 UTC" // from String()
	expectedMarshalString = `"2019-12-15 01:01:01.000000000"`
	expectedTime          = time.Date(2019, 12, 15, 1, 1, 1, 0, time.UTC)
)

func TestTimestampRFC3339String(t *testing.T) {
	ts := (RFC3339)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestTimestampRFC3339Marshal(t *testing.T) {
	ts := (RFC3339)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestTimestampRFC3339Unmarshal(t *testing.T) {
	unmarshalString := `"2019-12-15T01:01:01Z"`
	var ts RFC3339
	err := jsoniter.Unmarshal([]byte(unmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (RFC3339)(expectedTime), ts)
}

func TestTimestampANSICwithTZString(t *testing.T) {
	ts := (ANSICwithTZ)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestTimestampANSICwithTZMarshal(t *testing.T) {
	ts := (ANSICwithTZ)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestTimestampANSICwithTZUnmarshal(t *testing.T) {
	unmarshalString := `"Sun Dec 15 01:01:01 2019 UTC"`
	var ts ANSICwithTZ
	err := jsoniter.Unmarshal([]byte(unmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (ANSICwithTZ)(expectedTime), ts)
}

func TestTimestampUnixMillisecondString(t *testing.T) {
	ts := (UnixMillisecond)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestTimestampUnixMillisecondMarshal(t *testing.T) {
	ts := (UnixMillisecond)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestTimestampUnixMillisecondUnmarshal(t *testing.T) {
	unmarshalString := `1576371661000`
	var ts UnixMillisecond
	err := jsoniter.Unmarshal([]byte(unmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (UnixMillisecond)(expectedTime), ts)
}

func TestFluentdTimestampString(t *testing.T) {
	ts := (FluentdTimestamp)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestFluentdTimestampMarshal(t *testing.T) {
	ts := (FluentdTimestamp)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestFluentdTimestampUnmarshal(t *testing.T) {
	unmarshalString := `"2019-12-15 01:01:01 +0000"`
	var ts FluentdTimestamp
	err := jsoniter.Unmarshal([]byte(unmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (FluentdTimestamp)(expectedTime), ts)
}

func TestUnixFloatString(t *testing.T) {
	ts := (UnixFloat)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestUnixFloatMarshal(t *testing.T) {
	ts := (UnixFloat)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestUnixFloatUnmarshal(t *testing.T) {
	unmarshalString := `1541001600.580233`
	expectedTime := time.Date(2018, 10, 31, 16, 0, 0, 580233097, time.UTC)
	var ts UnixFloat
	err := jsoniter.Unmarshal([]byte(unmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (UnixFloat)(expectedTime), ts)
}

func TestSuricataString(t *testing.T) {
	ts := (SuricataTimestamp)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestSuricataMarshal(t *testing.T) {
	ts := (SuricataTimestamp)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestSuricataUnmarshal(t *testing.T) {
	unmarshalString := `"2015-10-22T11:17:43.787396+0100"`
	// Verify that hour has adjusted to UTC timezone
	expectedTime := time.Date(2015, 10, 22, 10, 17, 43, 787396000, time.UTC)
	var ts SuricataTimestamp
	err := jsoniter.Unmarshal([]byte(unmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (SuricataTimestamp)(expectedTime), ts)
}
