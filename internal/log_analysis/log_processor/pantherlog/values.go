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
	"sort"
	"sync"
)

// ValueWriter provides the interface to write field values
type ValueWriter interface {
	WriteValues(field FieldID, values ...string)
}

// ValueWriterTo can write field values to a ValueWriter
type ValueWriterTo interface {
	WriteValuesTo(w ValueWriter)
}

// ValueBuffer is a reusable buffer of field values.
// It provides helper methods to collect fields from log entries.
// A ValueBuffer can be reset and used in a pool.
type ValueBuffer struct {
	// Mark ValueBuffer as unsafe to pass by value
	noCopy noCopy //nolint:unused,structcheck

	index map[FieldID][]string
	dirty bool
}

var valueBufferPool = &sync.Pool{
	New: func() interface{} {
		return &ValueBuffer{}
	},
}

func BlankValueBuffer() *ValueBuffer {
	return valueBufferPool.Get().(*ValueBuffer)
}

func (b *ValueBuffer) Recycle() {
	if b == nil {
		return
	}
	b.Reset()
	valueBufferPool.Put(b)
}

func (b *ValueBuffer) IsEmpty() bool {
	return !b.dirty
}

// Contains checks if a field buffer contains a specific field.
func (b *ValueBuffer) Contains(id FieldID, value string) bool {
	if values, ok := b.index[id]; ok {
		for _, v := range values {
			if v == value {
				return true
			}
		}
	}
	return false
}

// Inspect returns a sorted copy snapshot of the value index
// This is mainly useful for tests.
func (b *ValueBuffer) Inspect() map[FieldID][]string {
	if b.index == nil {
		return nil
	}
	m := make(map[FieldID][]string, len(b.index))
	for id, values := range b.index {
		if values == nil {
			m[id] = nil
			continue
		}
		values := append([]string{}, values...)
		sort.Strings(values)
		m[id] = values
	}

	return m
}

// WriteValues adds values to the buffer.
func (b *ValueBuffer) WriteValues(id FieldID, values ...string) {
	currentValues := b.index[id]
	n := len(currentValues)
nextValue:
	for _, value := range values {
		// Don't add empty values
		if value == "" {
			continue
		}
		// Don't add duplicates
		for _, v := range currentValues {
			if v == value {
				continue nextValue
			}
		}
		currentValues = append(currentValues, value)
	}
	if len(currentValues) > n {
		if b.index == nil {
			b.index = make(map[FieldID][]string)
		}
		b.index[id] = currentValues
		b.dirty = true
	}
}

func (b *ValueBuffer) WriteValuesTo(w ValueWriter) {
	for id, values := range b.index {
		w.WriteValues(id, values...)
	}
}

// Reset clears all fields from a buffer retaining allocated memory.
func (b *ValueBuffer) Reset() {
	for id, values := range b.index {
		b.index[id] = values[:0]
	}
	b.dirty = false
}

// Get returns the values stored for a field id (sorted)
func (b *ValueBuffer) Get(id FieldID) []string {
	switch values := b.index[id]; len(values) {
	case 0:
		return nil
	case 1:
		return values
	default:
		sort.Strings(values)
		return values
	}
}

// Fields returns the field ids that contain values in this buffer.
func (b *ValueBuffer) Fields() []FieldID {
	if b.index == nil {
		return nil
	}
	ids := make([]FieldID, 0, len(b.index))
	for id, values := range b.index {
		if len(values) > 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return ids
}
