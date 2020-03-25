package timestamp

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
)

var (
	expectedString        = "2019-12-15 01:01:01 +0000 UTC" // from String()
	expectedMarshalString = `"2019-12-15 01:01:01.000000000"`
	expectedTime          = time.Date(2019, 12, 15, 1, 1, 1, 0, time.UTC)

	jsonUnmarshalString            = `"2019-12-15T01:01:01Z"`
	osqueryUnmarshalString         = `"Sun Dec 15 01:01:01 2019 UTC"`
	unixMillisecondUnmarshalString = `1576371661000`
	fluentdUnmarshalString         = `"2019-12-15 01:01:01 +0000"`
)

func TestTimestampRFC3339_String(t *testing.T) {
	ts := (RFC3339)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestTimestampRFC3339_Marshal(t *testing.T) {
	ts := (RFC3339)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestTimestampRFC3339_Unmarshal(t *testing.T) {
	var ts RFC3339
	err := jsoniter.Unmarshal([]byte(jsonUnmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (RFC3339)(expectedTime), ts)
}

func TestTimestampANSICwithTZ_String(t *testing.T) {
	ts := (ANSICwithTZ)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestTimestampANSICwithTZ_Marshal(t *testing.T) {
	ts := (ANSICwithTZ)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestTimestampANSICwithTZ_Unmarshal(t *testing.T) {
	var ts ANSICwithTZ
	err := jsoniter.Unmarshal([]byte(osqueryUnmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (ANSICwithTZ)(expectedTime), ts)
}

func TestTimestampUnixMillisecond_String(t *testing.T) {
	ts := (UnixMillisecond)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestTimestampUnixMillisecond_Marshal(t *testing.T) {
	ts := (UnixMillisecond)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestTimestampUnixMillisecond_Unmarshal(t *testing.T) {
	var ts UnixMillisecond
	err := jsoniter.Unmarshal([]byte(unixMillisecondUnmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (UnixMillisecond)(expectedTime), ts)
}

func TestFluentdTimestamp_String(t *testing.T) {
	ts := (FluentdTimestamp)(expectedTime)
	assert.Equal(t, expectedString, ts.String())
}

func TestFluentdTimestamp_Marshal(t *testing.T) {
	ts := (FluentdTimestamp)(expectedTime)
	jsonTS, err := jsoniter.Marshal(&ts)
	assert.NoError(t, err)
	assert.Equal(t, expectedMarshalString, string(jsonTS))
}

func TestFluentdTimestamp_Unmarshal(t *testing.T) {
	var ts FluentdTimestamp
	err := jsoniter.Unmarshal([]byte(fluentdUnmarshalString), &ts)
	assert.NoError(t, err)
	assert.Equal(t, (FluentdTimestamp)(expectedTime), ts)
}
