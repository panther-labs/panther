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
	"time"
)

// These objects are used to read timestamps and ensure a consistent JSON output for timestamps.

// NOTE: prefix the name of all objects with Timestamp so schema generation can automatically understand these.
// NOTE: the suffix of the names is meant to reflect the time format being read (unmarshal)

// We want our output JSON timestamps to be: YYYY-MM-DD HH:MM:SS.fffffffff
// https://aws.amazon.com/premiumsupport/knowledge-center/query-table-athena-timestamp-empty/
const (
	jsonMarshalLayout = `"2006-01-02 15:04:05.000000000"`

	ansicWithTZUnmarshalLayout = `"Mon Jan 2 15:04:05 2006 MST"` // similar to time.ANSIC but with MST
)

// use these functions to parse all incoming dates to ensure UTC consistency
func Parse(layout, value string) (RFC3339, error) {
	t, err := time.Parse(layout, value)
	return (RFC3339)(t.UTC()), err
}

func Unix(sec int64, nsec int64) RFC3339 {
	return (RFC3339)(time.Unix(sec, nsec).UTC())
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
	*ts = (ANSICwithTZ)(t)
	return
}
