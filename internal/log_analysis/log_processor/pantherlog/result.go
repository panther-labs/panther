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
	"time"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/rowid"
)

// Result is the result of parsing a log event.
type Result struct {
	CoreFields
	Meta   []FieldID
	Event  interface{}
	Values *ValueBuffer
	// Used for log events that embed parsers.PantherLog
	RawEvent interface{}
}

// WriteValues implements ValueWriter interface
func (r *Result) WriteValues(kind FieldID, values ...string) {
	if r.Values == nil {
		r.Values = &ValueBuffer{}
	}
	r.Values.WriteValues(kind, values...)
}

type resultEncoder struct{}

func (*resultEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	result := (*Result)(ptr)
	return result.Event == nil
}

func (*resultEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	result := (*Result)(ptr)
	// Hack around events with embedded parsers.PantherLog.
	// TODO: Remove this once all parsers are ported to not use parsers.PantherLog
	if raw := result.RawEvent; raw != nil {
		stream.WriteVal(raw)
		return
	}

	// Normal result
	values := result.Values
	if values == nil {
		result.Values = BlankValueBuffer()
	}
	att := stream.Attachment
	stream.Attachment = result
	stream.WriteVal(result.Event)
	stream.Attachment = att
	result.writeMeta(stream)
	if values == nil {
		// values were borrowed
		result.Values.Recycle()
	}
	result.Values = values
}

func (r *Result) writeMeta(stream *jsoniter.Stream) {
	if !extendJSON(stream.Buffer()) {
		stream.WriteObjectStart()
	}
	stream.WriteObjectField(FieldLogTypeJSON)
	stream.WriteString(r.PantherLogType)
	stream.WriteMore()

	stream.WriteObjectField(FieldRowIDJSON)
	stream.WriteString(r.PantherRowID)
	stream.WriteMore()

	stream.WriteObjectField(FieldEventTimeJSON)
	if eventTime := r.PantherEventTime; eventTime.IsZero() {
		stream.WriteVal(r.PantherParseTime)
	} else {
		stream.WriteVal(eventTime)
	}
	stream.WriteMore()

	stream.WriteObjectField(FieldParseTimeJSON)
	stream.WriteVal(r.PantherParseTime)

	for _, kind := range r.Meta {
		values := r.Values.Get(kind)
		if len(values) == 0 {
			continue
		}
		fieldName, ok := fieldNamesJSON[kind]
		if !ok {
			continue
		}
		stream.WriteMore()
		stream.WriteObjectField(fieldName)
		stream.WriteArrayStart()
		for i, value := range values {
			if i != 0 {
				stream.WriteMore()
			}
			stream.WriteString(value)
		}
		stream.WriteArrayEnd()
	}

	stream.WriteObjectEnd()
}

func extendJSON(data []byte) bool {
	// Swap JSON object closing brace ('}') with comma (',') to extend the object
	if n := len(data) - 1; 0 <= n && n < len(data) && data[n] == '}' {
		data[n] = ','
		return true
	}
	return false
}

// ResultBuilder builds new results filling out result fields.
type ResultBuilder struct {
	LogType   string
	Meta      []FieldID
	NextRowID func() string
	Now       func() time.Time
}

// BuildResult builds a new result for an event
func (b *ResultBuilder) BuildResult(event interface{}) (*Result, error) {
	return &Result{
		CoreFields: CoreFields{
			PantherLogType:   b.LogType,
			PantherRowID:     b.nextRowID(),
			PantherParseTime: b.now(),
		},
		Event: event,
		Meta:  b.meta(),
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

func (b *ResultBuilder) meta() []FieldID {
	if b.Meta != nil {
		return b.Meta
	}
	return defaultMetaFields
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
