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
	"sort"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/null"
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
)

// ValueBuffer is a reusable buffer of field values.
// It provides helper methods to collect fields from log entries.
// A ValueBuffer can be reset and used in a pool.
type ValueBuffer struct {
	index map[ValueKind]sort.StringSlice
}

// Contains checks if a field buffer contains a specific field.
func (b *ValueBuffer) Contains(field Value) bool {
	if values, ok := b.index[field.Kind]; ok {
		for _, value := range values {
			if value == field.Data {
				return true
			}
		}
	}
	return false
}

// AppendValuesTo appends all fields stored in the buffer to a slice.
// This is mainly useful for tests.
func (b *ValueBuffer) AppendValuesTo(values []Value) []Value {
	for kind, strValues := range b.index {
		for _, value := range strValues {
			values = append(values, Value{
				Kind: kind,
				Data: value,
			})
		}
	}
	return values
}

// WriteValues adds values to the buffer.
func (b *ValueBuffer) WriteValues(kind ValueKind, values ...string) {
	currentValues := b.index[kind]
	n := len(currentValues)
nextValue:
	for _, value := range values {
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
			b.index = make(map[ValueKind]sort.StringSlice)
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
}

// ValuesUnsorted returns unsorted field values
func (b *ValueBuffer) ValuesUnsorted(kind ValueKind) []string {
	if values := b.index[kind]; len(values) != 0 {
		return values
	}
	return nil
}

// Values returns field values sorted
func (b *ValueBuffer) Values(kind ValueKind) []string {
	switch values := b.index[kind]; len(values) {
	case 0:
		return nil
	case 1:
		return values
	default:
		sort.Sort(values)
		return values
	}
}

func NopValueWriter() ValueWriter {
	return &nopValueWriter{}
}

type nopValueWriter struct{}

func (*nopValueWriter) WriteValues(_ ValueKind, _ ...string) {}

// ValueKinds returns the kind of values this buffer contains.
func (b *ValueBuffer) ValueKinds() []ValueKind {
	kinds := make([]ValueKind, 0, len(b.index))
	for kind, values := range b.index {
		if len(values) > 0 {
			kinds = append(kinds, kind)
		}
	}
	return kinds
}

// Value is a value extracted from a log entry to be used in queries by Panther
type Value struct {
	Kind ValueKind
	Data string
}

// IsZero checks if a field is empty.
// Zero value fields can be returned by FieldFactory if the value is not valid for the specified FieldKind.
func (d Value) IsZero() bool {
	return d == Value{}
}

// ValueSlice is a helper type for sorting values
type ValueSlice []Value

var _ sort.Interface = (ValueSlice)(nil)

// Len implements sort.Interface
func (values ValueSlice) Len() int {
	return len(values)
}

// Swap implements sort.Interface
func (values ValueSlice) Swap(i, j int) {
	values[i], values[j] = values[j], values[i]
}

// Less implements sort.Interface
func (values ValueSlice) Less(i, j int) bool {
	a := &values[i]
	b := &values[j]
	if a.Kind == b.Kind {
		return a.Data < b.Data
	}
	return a.Kind < b.Kind
}

// WriteValues implements ValueWriter interface
func (values *ValueSlice) WriteValues(kind ValueKind, data ...string) {
	for _, d := range data {
		(*values) = append(*values, Value{
			Kind: kind,
			Data: d,
		})
	}
}

// Normalized returns a sorted copy of the values slice removing zero values.
// Sorting order is ascending over Kind, Data
func (values ValueSlice) Normalized() ValueSlice {
	if values == nil {
		return nil
	}
	norm := make([]Value, 0, len(values))
	for _, v := range values {
		if v.IsZero() {
			continue
		}
		norm = append(norm, v)
	}
	sort.Stable(ValueSlice(norm))
	return norm
}

// Specific types for extracting pantherlog values

type Domain null.String
type IPAddress null.String
type Hostname null.String
type SHA1 null.String
type SHA256 null.String
type MD5 null.String
type URL null.String
