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
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// ValueScanner parses values from a string and writes them to a ValueWriter.
// Implementations should parse `input` and write valid values to `w`.
// If errors occur while parsing `input` no values should be written to `w`.
type ValueScanner interface {
	// ScanValues scans `input` and writes values to `w`
	ScanValues(w ValueWriter, input string)
}

// ScannerFunc is a function implementing ValueScanner interface
type ScannerFunc func(dest ValueWriter, value string)

var _ ValueScanner = (ScannerFunc)(nil)

// ScanValues implements ValueScanner interface
func (f ScannerFunc) ScanValues(dest ValueWriter, value string) {
	f(dest, value)
}

var registeredScanners = map[string]*scannerEntry{}

type scannerEntry struct {
	Scanner ValueScanner
	Kinds   []ValueKind
}

func MustRegisterScanner(name string, scanner ValueScanner, kinds ...ValueKind) {
	if err := RegisterScanner(name, scanner, kinds...); err != nil {
		panic(err)
	}
}

func RegisterScanner(name string, scanner ValueScanner, kinds ...ValueKind) error {
	if name == "" {
		return errors.New("anonymous scanner")
	}
	if scanner == nil {
		return errors.New("nil scanner")
	}
	if err := checkKinds(kinds); err != nil {
		return err
	}
	if _, duplicate := registeredScanners[name]; duplicate {
		return errors.Errorf("duplicate scanner %q", name)
	}
	registeredScanners[name] = &scannerEntry{
		Scanner: scanner,
		Kinds:   kinds,
	}
	return nil
}

func checkKinds(kinds []ValueKind) error {
	if len(kinds) == 0 {
		return errors.New("no value kinds")
	}
	for _, kind := range kinds {
		if kind == KindNone {
			return errors.New("zero value kind")
		}
	}
	return nil
}

func LookupScanner(name string) (scanner ValueScanner, kinds []ValueKind) {
	if entry, ok := registeredScanners[name]; ok {
		scanner = entry.Scanner
		kinds = append(kinds, entry.Kinds...)
	}
	return
}

// ScanURL scans a URL string for domain or ip address
func ScanURL(dest ValueWriter, input string) {
	if input == "" {
		return
	}
	u, err := url.Parse(input)
	if err != nil {
		return
	}
	ScanHostname(dest, u.Hostname())
}

// ScanHostname scans `input` for either an ip address or a domain name value.
func ScanHostname(w ValueWriter, input string) {
	if checkIPAddress(input) {
		w.WriteValues(KindIPAddress, input)
	} else {
		w.WriteValues(KindDomainName, input)
	}
}

// ScanIPAddress scans `input` for an ip address value.
func ScanIPAddress(w ValueWriter, input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}
	if checkIPAddress(input) {
		w.WriteValues(KindIPAddress, input)
	}
}

// checkIPAddress checks if an IP address is valid
// TODO: [performance] Use a simpler method to check ip addresses than net.ParseIP to avoid allocations.
func checkIPAddress(addr string) bool {
	return net.ParseIP(addr) != nil
}

// ScanValues implements ValueScanner interface
func (kind ValueKind) ScanValues(w ValueWriter, input string) {
	w.WriteValues(kind, input)
}

type scanStringEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

func (enc *scanStringEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}
func (enc *scanStringEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((*string)(ptr))
	if input == "" {
		return
	}
	w, ok := stream.Attachment.(ValueWriter)
	if !ok {
		return
	}
	enc.scanner.ScanValues(w, input)
}

type scanStringerEncoder struct {
	parent   jsoniter.ValEncoder
	scanner  ValueScanner
	typ      reflect.Type
	indirect bool
}

func (enc *scanStringerEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

func (enc *scanStringerEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	w, ok := stream.Attachment.(ValueWriter)
	if !ok {
		return
	}
	val := reflect.NewAt(enc.typ, ptr)
	if enc.indirect {
		val = val.Elem()
	}
	str := val.Interface().(fmt.Stringer)
	if input := str.String(); input != "" {
		enc.scanner.ScanValues(w, input)
	}
}

type scanNullStringEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

func (enc *scanNullStringEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}

func (enc *scanNullStringEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((*null.String)(ptr))
	if !input.Exists || input.Value == "" {
		return
	}
	w, ok := stream.Attachment.(ValueWriter)
	if !ok {
		return
	}
	enc.scanner.ScanValues(w, input.Value)
}

type scanStringPtrEncoder struct {
	parent  jsoniter.ValEncoder
	scanner ValueScanner
}

func (enc *scanStringPtrEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return enc.parent.IsEmpty(ptr)
}
func (enc *scanStringPtrEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	enc.parent.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	input := *((**string)(ptr))
	if input == nil {
		return
	}
	w, ok := stream.Attachment.(ValueWriter)
	if !ok {
		return
	}
	enc.scanner.ScanValues(w, *input)
}

type scanValueEncodersExt struct {
	jsoniter.DummyExtension
}

var (
	typStringer   = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
	typString     = reflect.TypeOf("")
	typStringPtr  = reflect.TypeOf((*string)(nil))
	typNullString = reflect.TypeOf(null.String{})
)

func (ext *scanValueEncodersExt) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		field := binding.Field
		tag, ok := field.Tag().Lookup(TagName)
		if !ok {
			continue
		}
		scanner, _ := LookupScanner(tag)
		if scanner == nil {
			continue
		}
		fieldType := field.Type().Type1()
		// Decorate encoders
		switch {
		case fieldType.ConvertibleTo(typString):
			binding.Encoder = &scanStringEncoder{
				parent:  binding.Encoder,
				scanner: scanner,
			}
		case fieldType.ConvertibleTo(typStringPtr):
			binding.Encoder = &scanStringPtrEncoder{
				parent:  binding.Encoder,
				scanner: scanner,
			}
		case fieldType.ConvertibleTo(typNullString):
			binding.Encoder = &scanNullStringEncoder{
				parent:  binding.Encoder,
				scanner: scanner,
			}
		case reflect.PtrTo(fieldType).Implements(typStringer):
			binding.Encoder = &scanStringerEncoder{
				parent:  binding.Encoder,
				typ:     fieldType,
				scanner: scanner,
			}
		case fieldType.Implements(typStringer):
			indirect := fieldType.Kind() == reflect.Ptr
			binding.Encoder = &scanStringerEncoder{
				parent:   binding.Encoder,
				typ:      fieldType,
				indirect: indirect,
				scanner:  scanner,
			}
		}
	}
}
