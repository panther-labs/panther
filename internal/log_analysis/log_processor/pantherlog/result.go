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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/rowid"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type Result struct {
	// It is unsafe to use the same buffer and ValueBuffer from multiple instances.
	noCopy noCopy //nolint:unused,structcheck

	LogType   string
	EventTime time.Time
	ParseTime time.Time
	RowID     string
	JSON      []byte

	values ValueBuffer
}

func (r *Result) Clone() *Result {
	return &Result{
		LogType:   r.LogType,
		EventTime: r.EventTime,
		ParseTime: r.ParseTime,
		RowID:     r.RowID,
		JSON:      append(([]byte)(nil), r.JSON...),
	}
}

type resultWriter Result

func (r *resultWriter) Write(p []byte) (int, error) {
	r.JSON = append(r.JSON, p...)
	return len(p), nil
}

type ResultBuilder struct {
	Meta      Meta
	NextRowID func() string
	Now       func() time.Time
}

func StaticRowID(id string) func() string {
	return func() string {
		return id
	}
}

func StaticNow(now time.Time) func() time.Time {
	return func() time.Time {
		return now
	}
}

func (r *Result) WriteEvent(event Event, meta Meta) error {
	stream := jsonAPI.BorrowStream((*resultWriter)(r))
	var eventTime *time.Time
	r.LogType, eventTime = event.PantherLogEvent()
	if e, ok := event.(ValueWriterTo); ok {
		e.WriteValuesTo(&r.values)
	}
	if eventTime == nil {
		r.EventTime = r.ParseTime
	} else {
		r.EventTime = *eventTime
	}
	stream.Attachment = &r.values
	stream.WriteVal(event)
	r.writeMeta(meta, stream)
	err := stream.Flush()
	jsonAPI.ReturnStream(stream)
	return err
}

func (b *ResultBuilder) BuildResult(event Event) (*Result, error) {
	result := BlankResult()
	result.RowID = b.nextRowID()
	result.ParseTime = b.now()
	if err := result.WriteEvent(event, b.meta()); err != nil {
		result.Close()
		return nil, err
	}
	return result, nil
}

func (b *ResultBuilder) PackEvents(events []Event, err error) ([]*Result, error) {
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	results := make([]*Result, len(events))
	for i, event := range events {
		results[i], err = b.BuildResult(event)
		if err != nil {
			return nil, err
		}
	}
	return results, nil
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
func (b *ResultBuilder) meta() Meta {
	if b.Meta != nil {
		return b.Meta
	}
	return defaultMetaFields
}

const (
	FieldLogType   = FieldPrefix + "log_type"
	FieldRowID     = FieldPrefix + "row_id"
	FieldEventTime = FieldPrefix + "event_time"
	FieldParseTime = FieldPrefix + "parse_time"
)

func (r *Result) writeMeta(meta Meta, stream *jsoniter.Stream) {
	if !extendJSON(stream.Buffer()) {
		stream.WriteObjectStart()
	}
	stream.WriteObjectField(FieldLogType)
	stream.WriteString(r.LogType)
	stream.WriteMore()

	stream.WriteObjectField(FieldRowID)
	stream.WriteString(r.RowID)
	stream.WriteMore()

	stream.WriteObjectField(FieldEventTime)
	writeJSONTimestamp(stream, r.EventTime)
	stream.WriteMore()

	stream.WriteObjectField(FieldParseTime)
	writeJSONTimestamp(stream, r.ParseTime)

	for kind, values := range r.values.index {
		if len(values) == 0 {
			continue
		}
		metaField, ok := meta[kind]
		if !ok {
			continue
		}
		stream.WriteMore()
		stream.WriteObjectField(metaField.FieldNameJSON)
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

// avoid allocations when encoding timestamps
func writeJSONTimestamp(stream *jsoniter.Stream, tm time.Time) {
	stream.SetBuffer(timestamp.AppendJSON(stream.Buffer(), tm))
}

var resultPool = &sync.Pool{
	New: func() interface{} {
		return &Result{}
	},
}

func BlankResult() *Result {
	return resultPool.Get().(*Result)
}

func NewResult(event Event, rowID string, parseTime time.Time, meta Meta) (*Result, error) {
	result := BlankResult()
	result.RowID = rowID
	result.ParseTime = parseTime
	if meta == nil {
		meta = defaultMetaFields
	}
	if err := result.WriteEvent(event, meta); err != nil {
		result.Close()
		return nil, err
	}
	return result, nil
}

func (r *Result) Close() {
	if r == nil {
		return
	}
	r.values.Reset()
	*r = Result{
		JSON:   r.JSON[:0],
		values: r.values,
	}
	resultPool.Put(r)
}
