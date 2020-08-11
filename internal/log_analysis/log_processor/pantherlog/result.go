package pantherlog

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
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/rowid"
)

// Result is the result of parsing a log event.
type Result struct {
	// Result extends all core panther fields
	CoreFields
	// The underlying event
	Event interface{}
	// Used for log events that embed parsers.PantherLog. This is a low-overhead, temporary work-around
	// to avoid duplicate panther fields in resulting JSON.
	// FIXME: Remove this field once all parsers are ported to the new method.
	EventIncludesPantherFields bool
	// Collected indicator values for this result.
	// This field is normally nil throughout the lifetime of results.
	// It is populated temporarily by the custom jsoniter encoder for *Result to collect all indicator field values.
	values *ValueBuffer
}

// WriteValues implements ValueWriter interface
func (r *Result) WriteValues(kind FieldID, values ...string) {
	if r.values == nil {
		r.values = &ValueBuffer{}
	}
	r.values.WriteValues(kind, values...)
}

// ResultBuilder builds new results filling out result fields.
type ResultBuilder struct {
	// Override this to have static row ids for tests
	NextRowID func() string
	// Override this to have static parse time for tests
	Now func() time.Time
}

// EventTimer returns the event timestamp.
// ResultBuilder checks for events that implement this interface and uses the appropriate timestamp as the event time.
// Events that require custom logic to decide their timestamp should implement this interface.
type EventTimer interface {
	PantherEventTime() time.Time
}

// BuildResult builds a new result for an event.
// Log type is passed as an argument so that a single result builder can be reused for producing results of different
// log types.
func (b *ResultBuilder) BuildResult(logType string, event interface{}) (*Result, error) {
	var eventTime time.Time
	if e, ok := event.(EventTimer); ok {
		eventTime = e.PantherEventTime()
	}

	return &Result{
		CoreFields: CoreFields{
			PantherLogType:   logType,
			PantherRowID:     b.nextRowID(),
			PantherParseTime: b.now().UTC(),
			PantherEventTime: eventTime.UTC(),
		},
		Event: event,
	}, nil
}

func (b *ResultBuilder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}
func (b *ResultBuilder) nextRowID() string {
	if b.NextRowID != nil {
		return b.NextRowID()
	}
	return rowid.Next()
}

// StaticRowID returns a function to be used as ResultBuilder.NextRowID to always set the RowID to a specific value
func StaticRowID(id string) func() string {
	return func() string {
		return id
	}
}

// StaticNow returns a function to be used as ResultBuilder.Now to always set the ParseTime to a specific time
func StaticNow(now time.Time) func() time.Time {
	return func() time.Time {
		return now
	}
}

var (
	errJSONMarshal   = errors.New(`result can only be marshaled with jsoniter`)
	errJSONUnmarshal = errors.New(`result can only be unmarshaled with jsoniter`)
)

func (r *Result) MarshalJSON() ([]byte, error) {
	return nil, errJSONMarshal
}
func (r *Result) UnmarshalJSON(_ []byte) error {
	return errJSONUnmarshal
}
