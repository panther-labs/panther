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
	"net"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

// Field is a field value extracted from a log entry to be used in queries by Panther
type Field struct {
	Kind  FieldKind
	Value string
}

// IsZero checks if a field is empty.
// Zero value fields can be returned by FieldFactory if the value is not valid for the specified FieldKind.
func (f Field) IsZero() bool {
	return f == Field{}
}

// FieldKind is an enum of field types.
// Log parsers can register custom field types with `RegisterField`.
type FieldKind int

const (
	KindNone FieldKind = iota
	KindIPAddress
	KindDomainName
	KindMD5Hash
	KindSHA1Hash
	KindSHA256Hash
	KindHostname // Resolves to IPAddress or DomainName
)

// ParseFields implements FieldParser interface for registered fields
func (k FieldKind) ParseFields(fields []Field, value string) ([]Field, error) {
	entry, ok := fieldRegistry[k]
	if !ok {
		return fields, errors.Errorf("unregistered field kind %d", k)
	}
	field := entry.Factory(value)
	if field.IsZero() {
		return fields, errors.Errorf("empty field %q", entry.Name)
	}
	return append(fields, field), nil
}

// FieldBuffer is a reusable buffer of field values.
// It provides helper methods to collect fields from log entries.
// A FieldBuffer can be reset and used in a pool.
type FieldBuffer struct {
	scratch []Field
	Fields  map[FieldKind]sort.StringSlice
}

// Parse uses a parser to add fields from a string value.
// If the parser returns an error none of the fields parsed are added to the buffer.
func (b *FieldBuffer) Parse(value string, parser FieldParser) (err error) {
	b.scratch, err = parser.ParseFields(b.scratch[:0], value)
	if err == nil {
		for _, field := range b.scratch {
			b.Add(field)
		}
	}
	return
}

// Contains checks if a field buffer contains a specific field.
func (b *FieldBuffer) Contains(field Field) bool {
	if values, ok := b.Fields[field.Kind]; ok {
		for _, value := range values {
			if value == field.Value {
				return true
			}
		}
	}
	return false
}

// AppendFields appends all fields stored in the buffer to a slice.
// This is mainly useful for tests.
func (b *FieldBuffer) AppendFields(fields []Field) []Field {
	for kind, values := range b.Fields {
		for _, value := range values {
			fields = append(fields, Field{
				Kind:  kind,
				Value: value,
			})
		}
	}
	return fields
}

// Add adds a field to the buffer.
// Zero fields or duplicate field values are ignored.
func (b *FieldBuffer) Add(field Field) {
	if field.IsZero() {
		return
	}
	if b.Fields == nil {
		b.Fields = make(map[FieldKind]sort.StringSlice)
	}
	values := b.Fields[field.Kind]
	// Don't add duplicates
	for _, v := range values {
		if v == field.Value {
			return
		}
	}
	b.Fields[field.Kind] = append(values, field.Value)
}

// Reset clears all fields from a buffer retaining allocated memory.
func (b *FieldBuffer) Reset() {
	for kind, values := range b.Fields {
		b.Fields[kind] = values[:0]
	}
	b.scratch = b.scratch[:0]
}

// ValuesUnsorted returns unsorted field values
func (b *FieldBuffer) ValuesUnsorted(kind FieldKind) []string {
	return b.Fields[kind]
}

// Values returns field values sorted
func (b *FieldBuffer) Values(kind FieldKind) []string {
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

// FieldFactory creates a field from a string value.
// Implementations can return different kind of fields depending on input.
// Implementations should return a zero Field value if the input value is invalid.
type FieldFactory func(value string) Field

type fieldEntry struct {
	Name    string
	Factory FieldFactory
}

var fieldRegistry = map[FieldKind]*fieldEntry{}

func init() {
	RegisterField(KindIPAddress, "ip_address", IPAddress)
	RegisterField(KindDomainName, "domain", DomainName)
	RegisterField(KindHostname, "hostname", Hostname)
	RegisterField(KindMD5Hash, "md5", MD5Hash)
	RegisterField(KindSHA1Hash, "sha1", SHA1Hash)
	RegisterField(KindSHA256Hash, "sha256", SHA256Hash)
}

// RegisterField registers a field kind at init()
// Registered fields have a name and a factory function.
func RegisterField(kind FieldKind, name string, fac FieldFactory) {
	name = strings.TrimSpace(name)
	// Reserve negative field kind values
	if kind <= 0 {
		panic(errors.Errorf("invalid field kind %d", kind))
	}
	if name == "" {
		panic(errors.Errorf("empty field name %d", kind))
	}
	if fac == nil {
		panic(errors.Errorf("nil field factory %q", name))
	}
	if entry, duplicate := fieldRegistry[kind]; duplicate {
		panic(errors.Errorf("duplicate field kind %d %q, %q", kind, name, entry.Name))
	}
	fieldRegistry[kind] = &fieldEntry{
		Name:    name,
		Factory: fac,
	}
}

// IPAddress creates a new field for an ip address string
func IPAddress(addr string) Field {
	addr = strings.TrimSpace(addr)
	if checkIPAddress(addr) {
		return Field{KindIPAddress, addr}
	}
	return Field{}
}

// IPAddressP creates a new field for an ip address string pointer
func IPAddressP(addr *string) Field {
	if addr != nil {
		return IPAddress(*addr)
	}
	return Field{}
}

// SHA1Hash packs an SHA1 hash value to a Field
func SHA1Hash(hash string) Field {
	return Field{
		Kind:  KindSHA1Hash,
		Value: hash,
	}
}

func SHA1HashP(hash *string) Field {
	if hash != nil {
		return SHA1Hash(*hash)
	}
	return Field{}
}

// MD5Hash packs an MD5 hash value to a Field
func MD5Hash(hash string) Field {
	return Field{
		Kind:  KindMD5Hash,
		Value: hash,
	}
}

// MD5HashP packs an MD5 hash pointer value to a Field
func MD5HashP(hash *string) Field {
	if hash != nil {
		return MD5Hash(*hash)
	}
	return Field{}
}

// SHA256Hash packs an SHA256 hash value to a Field
func SHA256Hash(hash string) Field {
	return Field{
		Kind:  KindSHA256Hash,
		Value: hash,
	}
}

// SHA256Hash packs an SHA256 hash pointer value to a Field
func SHA256HashP(hash *string) Field {
	if hash != nil {
		return SHA256Hash(*hash)
	}
	return Field{}
}

// DomainName packs a domain name value to a Field
func DomainName(name string) Field {
	if name = strings.TrimSpace(name); name != "" {
		return Field{
			Value: name,
			Kind:  KindDomainName,
		}
	}
	return Field{}
}

func DomainNameP(name *string) Field {
	if name != nil {
		return DomainName(*name)
	}
	return Field{}
}

// Hostname returns either an IPAddress or a DomainName field
func Hostname(value string) Field {
	if value = strings.TrimSpace(value); value != "" {
		if checkIPAddress(value) {
			return Field{KindIPAddress, value}
		}
		return Field{KindDomainName, value}
	}
	return Field{}
}

// HostnameP returns either an IPAddress or a DomainName field from a pointer
func HostnameP(value *string) Field {
	if value != nil {
		return Hostname(*value)
	}
	return Field{}
}

// FieldSlice is a helper type for sorting fields
type FieldSlice []Field

var _ sort.Interface = (FieldSlice)(nil)

func (fields FieldSlice) Len() int {
	return len(fields)
}
func (fields FieldSlice) Swap(i, j int) {
	fields[i], fields[j] = fields[j], fields[i]
}

func (fields FieldSlice) Less(i, j int) bool {
	a := &fields[i]
	b := &fields[j]
	if a.Kind == b.Kind {
		return a.Value < b.Value
	}
	return a.Kind < b.Kind
}

// FieldParser parses fields from a string and appends them to a slice.
// Implementations should:
// - return the `fields` argument and nil error if the value was empty.
// - return the `fields` argument and an error if the value was invalid.
// - append all parsed fields to the `fields` argument and return it.
type FieldParser interface {
	// Parse fields appends fields parsed from value to fields
	ParseFields(fields []Field, value string) ([]Field, error)
}

// FieldParserFunc is a function implementing FieldParser interface
type FieldParserFunc func(fields []Field, value string) ([]Field, error)

var _ FieldParser = (FieldParserFunc)(nil)

// ParseFields implements FieldParser interface
func (f FieldParserFunc) ParseFields(fields []Field, value string) ([]Field, error) {
	return f(fields, value)
}

// NonEmptyParser returns a field parser that trims space and checks that a value is non empty.
func NonEmptyParser(kind FieldKind) FieldParser {
	return &fieldParserNonEmpty{kind}
}

type fieldParserNonEmpty struct {
	kind FieldKind
}

// ParseFields implements FieldParser interface
func (p *fieldParserNonEmpty) ParseFields(fields []Field, value string) ([]Field, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fields, nil
	}
	return append(fields, Field{
		Kind:  p.kind,
		Value: value,
	}), nil
}

type fieldParserIPAddress struct{}

// IPAddressParser parses an IP address field.
// It returns an error if the value is not valid IP address.
func IPAddressParser() FieldParser {
	return &fieldParserIPAddress{}
}

var _ FieldParser = (*fieldParserIPAddress)(nil)

// ParseFields implements FieldParser interface
func (*fieldParserIPAddress) ParseFields(fields []Field, value string) ([]Field, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fields, nil
	}
	if net.ParseIP(value) == nil {
		return fields, errors.Errorf("invalid ip address %q", value)
	}
	return append(fields, Field{
		Kind:  KindIPAddress,
		Value: value,
	}), nil
}

// HostNameParser parses a string to get either an IP address field or a domain field.
func HostNameParser() FieldParser {
	return &fieldParserHostname{}
}

type fieldParserHostname struct{}

var _ FieldParser = (*fieldParserHostname)(nil)

func (*fieldParserHostname) ParseFields(fields []Field, value string) ([]Field, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fields, nil
	}
	if net.ParseIP(value) != nil {
		return append(fields, Field{
			Kind:  KindIPAddress,
			Value: value,
		}), nil
	}
	return append(fields, Field{
		Kind:  KindDomainName,
		Value: value,
	}), nil
}

type GJSONFieldParser map[string]FieldParser

var _ FieldParser = (GJSONFieldParser)(nil)

func (g GJSONFieldParser) ParseFields(fields []Field, value string) ([]Field, error) {
	if value == "" {
		return fields, nil
	}
	if !gjson.Valid(value) {
		return fields, errors.Errorf("invalid JSON value %q", value)
	}
	var err error
	for path, parser := range g {
		if parser == nil {
			continue
		}
		// nolint:scope
		gjson.Get(value, path).ForEach(func(_, jsonValue gjson.Result) bool {
			fields, err = parser.ParseFields(fields, jsonValue.Str)
			return err == nil
		})
		if err != nil {
			break
		}
	}
	return fields, nil
}

// CheckIPAddress checks if an IP address is valid
func checkIPAddress(addr string) bool {
	return net.ParseIP(addr) != nil
}
