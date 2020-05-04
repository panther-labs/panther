// Package logs provides core structs and utilities for implementing parsers.
package logs

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
	"sync"
	"time"
)

// Event is an log event with collected fields
type Event struct {
	LogType   string
	Timestamp time.Time
	FieldBuffer
}

// eventPool is a package-wide pool of Event structs to minimize allocations
var eventPool = &sync.Pool{
	New: func() interface{} {
		return &Event{}
	},
}

// NewEvent creates a new event using a package-wide pool
func NewEvent(logType string, timestamp time.Time, fields ...Field) *Event {
	event := eventPool.Get().(*Event)
	event.LogType = logType
	event.Timestamp = timestamp
	for _, field := range fields {
		event.Add(field)
	}
	return event
}

// Reset clears the event keeping EventBuffer allocations
func (e *Event) Reset() {
	e.FieldBuffer.Reset()
	*e = Event{
		FieldBuffer: e.FieldBuffer,
	}
}

// Close resets the event and returns it to a package-wide pool to be reused
// Users must not use the event after calling close
func (e *Event) Close() {
	e.Reset()
	eventPool.Put(e)
}

// type EventEncoder struct {
// 	Now    func() time.Time
// 	NextID func() string
// 	Fields map[FieldKind]string
// }

// func (enc *EventEncoder) AppendJSON(dst []byte, row interface{}, event *Event) ([]byte, error) {
// 	offset := len(dst)
// 	w := AppendWriter{
// 		B: dst,
// 	}
// 	stream := jsoniter.ConfigFastest.BorrowStream(&w)
// 	defer jsoniter.ConfigFastest.ReturnStream(stream)
// 	stream.WriteVal(row)
// 	if stream.Error != nil {
// 		return dst, stream.Error
// 	}
// 	if len(w.B) == offset {
// 		return dst, errors.Errorf("empty row encoding")
// 	}
// 	w.WriteByte('\n')

// 	w.WriteByte('\n')

// 	return w.B, nil

// }

// var _ io.Writer = (*AppendWriter)(nil)

// type AppendWriter struct {
// 	B []byte
// }

// func (w *AppendWriter) WriteString(s string) (int, error) {
// 	w.B = append(w.B, s...)
// 	return len(s), nil
// }
// func (w *AppendWriter) WriteByte(b byte) error {
// 	w.B = append(w.B, b)
// 	return nil
// }
// func (w *AppendWriter) Write(p []byte) (int, error) {
// 	w.B = append(w.B, p...)
// 	return len(p), nil
// }

// func (e *Event) AppendJSON(dst []byte) ([]byte, error) {
// 	w := AppendWriter{B: dst}
// 	stream := jsoniter.ConfigFastest.BorrowStream(&w)
// 	defer jsoniter.ConfigFastest.ReturnStream(stream)
// 	n := 0
// 	stream.WriteObjectStart()
// 	for kind, set := range e.Fields {
// 		if set == nil {
// 			continue
// 		}
// 		values := set.Values
// 		if len(values) == 0 {
// 			continue
// 		}
// 		if n > 0 {
// 			stream.WriteMore()
// 		}
// 		n++
// 		stream.WriteObjectField(kind.String())
// 		stream.WriteArrayStart()
// 		sort.Strings(values)
// 		prev := values[0]
// 		stream.WriteString(prev)
// 		for _, v := range values[1:] {

// 			if v == prev {
// 				continue
// 			}
// 			stream.WriteMore()
// 			stream.WriteString(v)
// 			prev = v
// 		}
// 		stream.WriteArrayEnd()
// 	}
// 	stream.WriteObjectEnd()
// 	return w.B, nil
// }

// func (e *Event) MarshalJSON() ([]byte, error) {
// 	return e.AppendJSON(nil)
// }
