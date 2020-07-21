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
)

type ValueWriter interface {
	WriteValues(kind ValueKind, values ...string)
}

type ValueWriterTo interface {
	WriteValuesTo(w ValueWriter)
}

// ValueKind is an enum of value types.
type ValueKind int

const (
	KindNone ValueKind = iota
	KindIPAddress
	KindDomainName
	KindMD5Hash
	KindSHA1Hash
	KindSHA256Hash
	KindTraceID
)

// ValueBuffer is a reusable buffer of field values.
// It provides helper methods to collect fields from log entries.
// A ValueBuffer can be reset and used in a pool.
type ValueBuffer struct {
	index map[ValueKind][]string
	dirty bool
}

func (b *ValueBuffer) IsEmpty() bool {
	return !b.dirty
}

// Contains checks if a field buffer contains a specific field.
func (b *ValueBuffer) Contains(kind ValueKind, value string) bool {
	if values, ok := b.index[kind]; ok {
		for _, v := range values {
			if v == value {
				return true
			}
		}
	}
	return false
}

func (b *ValueBuffer) Clone() ValueBuffer {
	if b.index == nil {
		return ValueBuffer{}
	}
	c := ValueBuffer{
		index: make(map[ValueKind][]string, len(b.index)),
	}
	for kind, values := range b.index {
		if len(values) == 0 {
			continue
		}
		c.index[kind] = append([]string(nil), values...)
	}
	return c
}

// Inspect returns a sorted copy snapshot of the value index
// This is mainly useful for tests.
func (b *ValueBuffer) Inspect() map[ValueKind][]string {
	if b.index == nil {
		return nil
	}
	m := make(map[ValueKind][]string, len(b.index))
	for kind, values := range b.index {
		if values == nil {
			m[kind] = nil
			continue
		}
		values := append([]string{}, values...)
		sort.Strings(values)
		m[kind] = values
	}

	return m
}

// WriteValues adds values to the buffer.
func (b *ValueBuffer) WriteValues(kind ValueKind, values ...string) {
	currentValues := b.index[kind]
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
			b.index = make(map[ValueKind][]string)
		}
		b.index[kind] = currentValues
	}
}

func (b *ValueBuffer) WriteValuesTo(w ValueWriter) {
	for kind, values := range b.index {
		w.WriteValues(kind, values...)
	}
}

// Reset clears all fields from a buffer retaining allocated memory.
func (b *ValueBuffer) Reset() {
	for kind, values := range b.index {
		b.index[kind] = values[:0]
	}
	b.dirty = false
}

// Get returns field values sorted
func (b *ValueBuffer) Get(kind ValueKind) []string {
	switch values := b.index[kind]; len(values) {
	case 0:
		return nil
	case 1:
		return values
	default:
		sort.Strings(values)
		return values
	}
}

// Kinds returns the kind of values this buffer contains.
func (b *ValueBuffer) Kinds() []ValueKind {
	if b.index == nil {
		return nil
	}
	kinds := make([]ValueKind, 0, len(b.index))
	for kind, values := range b.index {
		if len(values) > 0 {
			kinds = append(kinds, kind)
		}
	}
	sort.Slice(kinds, func(i, j int) bool {
		return kinds[i] < kinds[j]
	})
	return kinds
}
