// package pantherlog provides core structs and utilities for implementing parsers.
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
	"sync"
	"time"
)

// Event is an log event with collected fields
type Event struct {
	LogType   string
	Timestamp time.Time
	ValueBuffer
}

// Eventer is the interface to be implemented by log events to provide `pantherlog` metadata
type Eventer interface {
	PantherLogEvent() *Event
}

// eventPool is a package-wide pool of Event structs to minimize allocations
var eventPool = &sync.Pool{
	New: func() interface{} {
		return &Event{}
	},
}

// NewEvent creates a new event using a package-wide pool
func NewEvent(logType string, timestamp time.Time, fields ...Value) *Event {
	event := eventPool.Get().(*Event)
	event.LogType = logType
	event.Timestamp = timestamp.UTC()
	for _, field := range fields {
		event.Add(field)
	}
	return event
}

// Reset clears the event keeping EventBuffer allocations
func (e *Event) Reset() {
	e.ValueBuffer.Reset()
	*e = Event{
		ValueBuffer: e.ValueBuffer,
	}
}

// Close resets the event and returns it to a package-wide pool to be reused
// Users must not use the event after calling close
func (e *Event) Close() {
	e.Reset()
	eventPool.Put(e)
}
