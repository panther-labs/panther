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
	"io"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/rowid"
)

// Result is the result of parsing a log event.
type Result struct {
	LogType   string
	Meta      Meta
	EventTime time.Time
	ParseTime time.Time
	RowID     string
	Event     interface{}
	Values    *ValueBuffer
}

// WriteValues implements ValueWriter interface
func (r *Result) WriteValues(kind ValueKind, values ...string) {
	if r.Values == nil {
		r.Values = &ValueBuffer{}
	}
	r.Values.WriteValues(kind, values...)
}

// WriteJSONTo writes the JSON for a Result to an io.Writer using the default result buffer pool
func (r *Result) WriteJSONTo(w io.Writer) error {
	return defaultPool.WriteResultTo(w, r)
}

func (r *Result) writeMeta(stream *jsoniter.Stream) {
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
	if eventTime := r.EventTime; eventTime.IsZero() {
		stream.WriteVal(r.ParseTime)
	} else {
		stream.WriteVal(eventTime)
	}
	stream.WriteMore()

	stream.WriteObjectField(FieldParseTime)
	stream.WriteVal(r.ParseTime)

	for kind, values := range r.Values.index {
		if len(values) == 0 {
			continue
		}
		metaField, ok := r.Meta[kind]
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

// ResultBuffer is a reusable buffer for serializing Results
type ResultBuffer struct {
	// It is unsafe to use the same buffer and ResultBuffer from multiple instances.
	noCopy noCopy //nolint:unused,structcheck

	values ValueBuffer
	stream *jsoniter.Stream
	pool   *ResultBufferPool
}

const (
	defaultBufferSize = 8192
	minBufferSize     = 512
)

var defaultPool = &ResultBufferPool{
	JSON:       JSON(),
	BufferSize: defaultBufferSize,
}

// BlankResultBuffer borrows a blank result buffer from the default pool
func BlankResultBuffer() *ResultBuffer {
	return defaultPool.Get()
}

func (b *ResultBuffer) Recycle() {
	if pool := b.pool; pool != nil {
		pool.put(b)
	}
}

// Reset resets the buffer to be reused.
func (b *ResultBuffer) Reset() {
	if !b.values.IsEmpty() {
		b.values.Reset()
	}
	b.stream.Reset(nil)
	b.stream.Error = nil
	b.stream.Attachment = nil
}

// ResultBuilder builds new results filling out result fields.
type ResultBuilder struct {
	LogType   string
	Meta      Meta
	NextRowID func() string
	Now       func() time.Time
}

// BuildResult builds a new result for an event
func (b *ResultBuilder) BuildResult(event interface{}) (*Result, error) {
	return &Result{
		LogType:   b.LogType,
		RowID:     b.nextRowID(),
		ParseTime: b.now(),
		Event:     event,
		Meta:      b.meta(),
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
func (b *ResultBuilder) meta() Meta {
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

type ResultBufferPool struct {
	pool sync.Pool

	JSON       jsoniter.API
	BufferSize int
}

func (p *ResultBufferPool) WriteResultTo(w io.Writer, result *Result) error {
	b := p.Get()
	defer p.put(b)
	return b.WriteResultTo(w, result)
}

func (b *ResultBuffer) WriteResultTo(w io.Writer, result *Result) error {
	stream := b.stream
	stream.Reset(w)

	// Use buffer values if result has no values set
	values := result.Values
	if values == nil {
		if !b.values.IsEmpty() {
			b.values.Reset()
		}
		result.Values = &b.values
	}
	stream.Attachment = result
	stream.WriteVal(result.Event)
	result.writeMeta(stream)

	// Restore result values
	result.Values = values

	err := stream.Flush()
	return err
}

func (p *ResultBufferPool) Get() *ResultBuffer {
	if buffer, ok := p.pool.Get().(*ResultBuffer); ok {
		return buffer
	}
	return p.newBuffer()
}

func (p *ResultBufferPool) put(b *ResultBuffer) {
	b.Reset()
	p.pool.Put(b)
}

func (p *ResultBufferPool) newBuffer() *ResultBuffer {
	api := p.JSON
	if api == nil {
		// Use package default JSON API as default
		api = JSON()
	}
	bufSize := p.BufferSize
	if bufSize < minBufferSize {
		bufSize = minBufferSize
	}
	return &ResultBuffer{
		pool:   p,
		stream: jsoniter.NewStream(api, nil, bufSize),
	}
}
