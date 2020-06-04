package timestamp

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
	"math"
	"strconv"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

// These objects are used to read timestamps and ensure a consistent JSON output for timestamps.

// NOTE: prefix the name of all objects with Timestamp so schema generation can automatically understand these.
// NOTE: the suffix of the names is meant to reflect the time format being read (unmarshal)

// We want our output JSON timestamps to be: YYYY-MM-DD HH:MM:SS.fffffffff
// https://aws.amazon.com/premiumsupport/knowledge-center/query-table-athena-timestamp-empty/
const (
	jsonMarshalLayout = `"2006-01-02 15:04:05.000000000"`

	ansicWithTZUnmarshalLayout = `"Mon Jan 2 15:04:05 2006 MST"` // similar to time.ANSIC but with MST

	fluentdTimestampLayout = `"2006-01-02 15:04:05 -0700"`

	suricataTimestampLayout = `"2006-01-02T15:04:05.999999999Z0700"`
)

func init() {
	awsglue.RegisterMapping(RFC3339{}, awsglue.GlueTimestampType)
	awsglue.RegisterMapping(ANSICwithTZ{}, awsglue.GlueTimestampType)
	awsglue.RegisterMapping(UnixMillisecond{}, awsglue.GlueTimestampType)
	awsglue.RegisterMapping(UnixFloat{}, awsglue.GlueTimestampType)
	awsglue.RegisterMapping(FluentdTimestamp{}, awsglue.GlueTimestampType)
	awsglue.RegisterMapping(SuricataTimestamp{}, awsglue.GlueTimestampType)
}

// use these functions to parse all incoming dates to ensure UTC consistency
func Parse(layout, value string) (RFC3339, error) {
	t, err := time.Parse(layout, value)
	return (RFC3339)(t.UTC()), err
}

func Unix(sec int64, nsec int64) RFC3339 {
	return (RFC3339)(time.Unix(sec, nsec).UTC())
}

func Now() RFC3339 {
	return (RFC3339)(time.Now().UTC())
}

type RFC3339 time.Time

func (ts *RFC3339) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *RFC3339) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *RFC3339) UnmarshalJSON(jsonBytes []byte) (err error) {
	return (*time.Time)(ts).UnmarshalJSON(jsonBytes)
}

// Like time.ANSIC but with MST
type ANSICwithTZ time.Time

func (ts *ANSICwithTZ) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *ANSICwithTZ) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *ANSICwithTZ) UnmarshalJSON(text []byte) (err error) {
	t, err := time.Parse(ansicWithTZUnmarshalLayout, string(text))
	if err != nil {
		return
	}
	*ts = (ANSICwithTZ)(t.UTC())
	return
}

// UnixMillisecond for JSON timestamps that are in unix epoch milliseconds
type UnixMillisecond time.Time

func (ts *UnixMillisecond) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *UnixMillisecond) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *UnixMillisecond) UnmarshalJSON(jsonBytes []byte) (err error) {
	value, err := strconv.ParseInt(string(jsonBytes), 10, 64)
	if err != nil {
		return err
	}
	t := time.Unix(0, value*time.Millisecond.Nanoseconds())
	*ts = (UnixMillisecond)(t.UTC())
	return nil
}

type FluentdTimestamp time.Time

func (ts *FluentdTimestamp) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *FluentdTimestamp) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *FluentdTimestamp) UnmarshalJSON(jsonBytes []byte) (err error) {
	t, err := time.Parse(fluentdTimestampLayout, string(jsonBytes))
	if err != nil {
		return
	}
	*ts = (FluentdTimestamp)(t.UTC())
	return
}

type SuricataTimestamp time.Time

func (ts *SuricataTimestamp) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}

func (ts *SuricataTimestamp) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}

func (ts *SuricataTimestamp) UnmarshalJSON(jsonBytes []byte) (err error) {
	t, err := time.Parse(suricataTimestampLayout, string(jsonBytes))
	if err != nil {
		return
	}
	*ts = (SuricataTimestamp)(t.UTC())
	return
}

// UnixFloat for JSON timestamps that are in unix seconds + fractions of a second
type UnixFloat time.Time

func (ts *UnixFloat) String() string {
	return (*time.Time)(ts).UTC().String() // ensure UTC
}
func (ts *UnixFloat) MarshalJSON() ([]byte, error) {
	return []byte((*time.Time)(ts).UTC().Format(jsonMarshalLayout)), nil // ensure UTC
}
func (ts *UnixFloat) UnmarshalJSON(jsonBytes []byte) (err error) {
	f, err := strconv.ParseFloat(string(jsonBytes), 64)
	if err != nil {
		return err
	}
	intPart, fracPart := math.Modf(f)
	t := time.Unix(int64(intPart), int64(fracPart*1e9))
	*ts = (UnixFloat)(t.UTC())
	return nil
}
