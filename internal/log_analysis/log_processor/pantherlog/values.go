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
	"net"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

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
	scratch []Value // a temporary field buffer for parsing fields
	Fields  map[ValueKind]sort.StringSlice
}

// Parse uses a parser to add fields from a string value.
// If the parser returns an error *none* of the fields parsed are added to the buffer.
func (b *ValueBuffer) Scan(value string, parser ValueScanner) (err error) {
	b.scratch, err = parser.ScanValues(b.scratch[:0], value)
	if err == nil {
		for _, field := range b.scratch {
			b.Add(field)
		}
	}
	return
}

// Contains checks if a field buffer contains a specific field.
func (b *ValueBuffer) Contains(field Value) bool {
	if values, ok := b.Fields[field.Kind]; ok {
		for _, value := range values {
			if value == field.Data {
				return true
			}
		}
	}
	return false
}

// AppendFieldsTo appends all fields stored in the buffer to a slice.
// This is mainly useful for tests.
func (b *ValueBuffer) AppendFieldsTo(fields []Value) []Value {
	for kind, values := range b.Fields {
		for _, value := range values {
			fields = append(fields, Value{
				Kind: kind,
				Data: value,
			})
		}
	}
	return fields
}

// Add adds a field to the buffer.
// Zero fields or duplicate field values are ignored.
func (b *ValueBuffer) Add(field Value) {
	if field.IsZero() {
		return
	}
	if b.Fields == nil {
		b.Fields = make(map[ValueKind]sort.StringSlice)
	}
	values := b.Fields[field.Kind]
	// Don't add duplicates
	for _, v := range values {
		if v == field.Data {
			return
		}
	}
	b.Fields[field.Kind] = append(values, field.Data)
}

// Reset clears all fields from a buffer retaining allocated memory.
func (b *ValueBuffer) Reset() {
	for kind, values := range b.Fields {
		b.Fields[kind] = values[:0]
	}
	b.scratch = b.scratch[:0]
}

// ValuesUnsorted returns unsorted field values
func (b *ValueBuffer) ValuesUnsorted(kind ValueKind) []string {
	if values := b.Fields[kind]; len(values) != 0 {
		return values
	}
	return nil
}

// Values returns field values sorted
func (b *ValueBuffer) Values(kind ValueKind) []string {
	switch values := b.Fields[kind]; len(values) {
	case 0:
		return nil
	case 1:
		return values
	default:
		sort.Sort(values)
		return values
	}
}

// IPAddress creates a new field for an ip address string
func IPAddress(addr string) Value {
	addr = strings.TrimSpace(addr)
	if checkIPAddress(addr) {
		return Value{KindIPAddress, addr}
	}
	return Value{}
}

// SHA1Hash packs an SHA1 hash value to a Field
func SHA1Hash(hash string) Value {
	return Value{
		Kind: KindSHA1Hash,
		Data: hash,
	}
}

// MD5Hash packs an MD5 hash value to a Field
func MD5Hash(hash string) Value {
	return Value{
		Kind: KindMD5Hash,
		Data: hash,
	}
}

// SHA256Hash packs an SHA256 hash value to a Field
func SHA256Hash(hash string) Value {
	return Value{
		Kind: KindSHA256Hash,
		Data: hash,
	}
}

// DomainName packs a domain name value to a Field
func DomainName(name string) Value {
	if name = strings.TrimSpace(name); name != "" {
		return Value{
			Data: name,
			Kind: KindDomainName,
		}
	}
	return Value{}
}

// Hostname returns either an IPAddress or a DomainName field
func Hostname(value string) Value {
	if value = strings.TrimSpace(value); value != "" {
		if checkIPAddress(value) {
			return Value{KindIPAddress, value}
		}
		return Value{KindDomainName, value}
	}
	return Value{}
}

// ValueSlice is a helper type for sorting fields
type ValueSlice []Value

var _ sort.Interface = (ValueSlice)(nil)

func (values ValueSlice) Len() int {
	return len(values)
}
func (values ValueSlice) Swap(i, j int) {
	values[i], values[j] = values[j], values[i]
}

func (values ValueSlice) Less(i, j int) bool {
	a := &values[i]
	b := &values[j]
	if a.Kind == b.Kind {
		return a.Data < b.Data
	}
	return a.Kind < b.Kind
}

// ValueScanner parses values from a string and appends them to a slice.
// Implementations should:
// - return the `values` argument and nil error if no values were found.
// - return the `values` argument and an error if an error occurred while parsing the string.
// - append all parsed values to the `values` argument and return it.
type ValueScanner interface {
	// Parse fields appends fields parsed from value to fields
	ScanValues(values []Value, input string) ([]Value, error)
}

// FieldParserFunc is a function implementing FieldParser interface
type ScannerFunc func(fields []Value, value string) ([]Value, error)

var _ ValueScanner = (ScannerFunc)(nil)

// ScanValues implements ValueScanner interface
func (f ScannerFunc) ScanValues(values []Value, value string) ([]Value, error) {
	return f(values, value)
}

// NonEmptyScanner returns a field parser that trims space and checks that a value is non empty.
func NonEmptyScanner(kind ValueKind) ValueScanner {
	return &scannerNonEmpty{kind}
}

type scannerNonEmpty struct {
	kind ValueKind
}

// ScanValues implements ValueScanner interface
func (p *scannerNonEmpty) ScanValues(values []Value, value string) ([]Value, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return values, nil
	}
	return append(values, Value{
		Kind: p.kind,
		Data: value,
	}), nil
}

type scannerIPAddress struct{}

// IPAddressScanner parses an IP address field.
// It returns an error if the value is not valid IP address.
func IPAddressScanner() ValueScanner {
	return &scannerIPAddress{}
}

var _ ValueScanner = (*scannerIPAddress)(nil)

// ScanValues implements ValueScanner interface
func (*scannerIPAddress) ScanValues(values []Value, value string) ([]Value, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return values, nil
	}
	if checkIPAddress(value) {
		return append(values, Value{
			Kind: KindIPAddress,
			Data: value,
		}), nil
	}
	return values, errors.Errorf("invalid ip address %q", value)
}

// HostnameScanner parses a string to get either an IP address field or a domain field.
func HostnameScanner() ValueScanner {
	return &scannerHostname{}
}

type scannerHostname struct{}

var _ ValueScanner = (*scannerHostname)(nil)

func (*scannerHostname) ScanValues(values []Value, value string) ([]Value, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return values, nil
	}
	if checkIPAddress(value) {
		return append(values, Value{
			Kind: KindIPAddress,
			Data: value,
		}), nil
	}
	return append(values, Value{
		Kind: KindDomainName,
		Data: value,
	}), nil
}

// ScannerGJSON extracts fields from JSON objects
type ScannerGJSON map[string]ValueScanner

var _ ValueScanner = (ScannerGJSON)(nil)

// ScanValues implements ValueScanner interface
func (g ScannerGJSON) ScanValues(values []Value, value string) ([]Value, error) {
	if value == "" {
		return values, nil
	}
	if !gjson.Valid(value) {
		return values, errors.Errorf("invalid JSON value %q", value)
	}
	var err error
	for path, parser := range g {
		if parser == nil {
			continue
		}
		// nolint:scope
		gjson.Get(value, path).ForEach(func(_, jsonValue gjson.Result) bool {
			values, err = parser.ScanValues(values, jsonValue.Str)
			return err == nil
		})
		if err != nil {
			break
		}
	}
	return values, nil
}

// CheckIPAddress checks if an IP address is valid
func checkIPAddress(addr string) bool {
	return net.ParseIP(addr) != nil
}
