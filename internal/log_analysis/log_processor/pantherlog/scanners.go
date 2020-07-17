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
	"net"
	"net/url"
	"reflect"
	"strings"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/null"
)

// ValueScanner parses values from a string and writes them to a ValueWriter.
// Implementations should return any errors that occurred while parsing a non-empty input string.
type ValueScanner interface {
	// ScanValues scans input and writes values to `dest`
	ScanValues(dest ValueWriter, input string) error
}

// ScannerFunc is a function implementing ValueScanner interface
type ScannerFunc func(dest ValueWriter, value string) error

var _ ValueScanner = (ScannerFunc)(nil)

// ScanValues implements ValueScanner interface
func (f ScannerFunc) ScanValues(dest ValueWriter, value string) error {
	return f(dest, value)
}

// NonEmptyScanner returns a value scanner that trims space and checks that a value is non empty.
func NonEmptyScanner(kind ValueKind) ValueScanner {
	return &scannerNonEmpty{kind}
}

type scannerNonEmpty struct {
	kind ValueKind
}

// ScanValues implements ValueScanner interface
func (p *scannerNonEmpty) ScanValues(dest ValueWriter, input string) error {
	if input = strings.TrimSpace(input); input != "" {
		dest.WriteValues(p.kind, input)
	}
	return nil
}

// ScanIPAddress scans `input` for an ip address value.
func ScanIPAddress(dest ValueWriter, input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	if checkIPAddress(input) {
		dest.WriteValues(KindIPAddress, input)
		return nil
	}
	return errors.Errorf("invalid ip address %q", input)
}

// ScanHostname scans `input` for either an ip address or a domain name value.
func ScanHostname(dest ValueWriter, input string) error {
	if input = strings.TrimSpace(input); input != "" && checkIPAddress(input) {
		dest.WriteValues(KindIPAddress, input)
	} else {
		dest.WriteValues(KindDomainName, input)
	}
	return nil
}

// ScanURL scans a URL string for domain or ip address
func ScanURL(dest ValueWriter, input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	u, err := url.Parse(input)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}
	if checkIPAddress(host) {
		dest.WriteValues(KindIPAddress, host)
	} else {
		dest.WriteValues(KindDomainName, host)
	}
	return nil
}

// GJSONScanner extracts values from JSON objects
type gjsonScanner struct {
	paths    []string
	scanners []ValueScanner
}

func NewGJSONScanner(paths map[string]ValueScanner) ValueScanner {
	s := gjsonScanner{}
	for path, scanner := range paths {
		if path != "" && scanner != nil {
			s.paths = append(s.paths, path)
			s.scanners = append(s.scanners, scanner)
		}
	}
	return &s
}

var _ ValueScanner = (*gjsonScanner)(nil)

// ScanValues implements ValueScanner interface
func (g *gjsonScanner) ScanValues(dest ValueWriter, input string) error {
	if input == "" {
		return nil
	}
	if !gjson.Valid(input) {
		return errors.Errorf("invalid JSON value %q", input)
	}
	results := gjson.GetMany(input, g.paths...)
	for i, result := range results {
		if str := result.Str; str != "" {
			if err := g.scanners[i].ScanValues(dest, str); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckIPAddress checks if an IP address is valid
// TODO: [performance] Use a simpler method to check ip addresses than net.ParseIP to avoid allocations.
func checkIPAddress(addr string) bool {
	return net.ParseIP(addr) != nil
}

// QuietScan scans for values dropping errors.
func QuietScan(s ValueScanner) ValueScanner {
	if s, ok := s.(*scannerQuiet); ok {
		return s
	}
	return &scannerQuiet{
		ValueScanner: s,
	}
}

type scannerQuiet struct {
	ValueScanner
}

func (s *scannerQuiet) ScanValues(dest ValueWriter, input string) error {
	_ = s.ValueScanner.ScanValues(dest, input)
	return nil
}

// This special encoder is used to parse a string value and extract pantherlog.Value from it in a single pass.
// This leverages the `jsoniter.Stream`'s `Attachment` field to store values as the stream walks through the object.
// The types using this encoder must be convertible to `null.String`.
type scanStringEncoder struct {
	scanner ValueScanner
}

var _ jsoniter.ValEncoder = (*scanStringEncoder)(nil)

func (s *scanStringEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	v := (*null.String)(ptr)
	return !v.Exists
}

func NewScanEncoder(scanner ValueScanner) jsoniter.ValEncoder {
	return &scanStringEncoder{
		scanner: scanner,
	}
}

func (s *scanStringEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	v := (*null.String)(ptr)
	if !v.Exists {
		stream.WriteNil()
		return
	}
	stream.WriteString(v.Value)
	if s.scanner == nil {
		return
	}
	if w, ok := stream.Attachment.(ValueWriter); ok {
		if err := s.scanner.ScanValues(w, v.Value); err != nil {
			stream.Error = err
		}
	}
}

// Index of special string types that extract pantherlog Values during JSON encoding.
// These types use a decoder that scans the decoded string value with a ValueScanner to extract pantherlog values
// in a single pass while decoding input JSON.
// To achieve that they check the iterator instance for a `*ValueBuffer` attachment and use it in the `ScanValues`
// method of their respective ValueScanner.
// Each entry in this index also contains a list of *all* possible `ValueKind` values that the scanner can produce.
// This information can be retrieved with the RegisteredValueKinds() package method.
var scannerMappings = map[reflect.Type][]ValueKind{}

func MustRegisterStringMapping(typ reflect.Type, scanner ValueScanner, kinds ...ValueKind) {
	if err := RegisterStringMapping(typ, scanner, kinds...); err != nil {
		panic(err)
	}
}

func RegisterStringMapping(typ reflect.Type, scanner ValueScanner, kinds ...ValueKind) error {
	if scanner == nil {
		return errors.New("nil scanner")
	}
	if len(kinds) == 0 {
		return errors.New("no value kinds")
	}
	for _, kind := range kinds {
		if kind == KindNone {
			return errors.New("zero value kind")
		}
	}

	if typ == nil {
		return errors.New("nil type")
	}

	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if !typ.ConvertibleTo(reflect.TypeOf(null.String{})) {
		return errors.New("type cannot be converted to null.String")
	}

	typName := typ.String()
	if typName == "" {
		return errors.New("anonymous type")
	}

	if _, duplicate := scannerMappings[typ]; duplicate {
		return errors.New("duplicate scanner mapping")
	}

	scannerMappings[typ] = kinds
	// Register in global jsoniter
	jsoniter.RegisterTypeDecoder(typName, null.StringDecoder())
	encoder := NewScanEncoder(scanner)
	jsoniter.RegisterTypeEncoder(typName, encoder)
	// Register in local jsoniter instance
	typ2 := reflect2.Type2(typ)
	customEncoders.encoders[typ2] = encoder
	return nil
}

func RegisteredValueKinds(typ reflect.Type) (kinds []ValueKind) {
	if entry, ok := scannerMappings[typ]; ok {
		return append(kinds, entry...)
	}
	return nil
}

func init() {
	MustRegisterStringMapping(reflect.TypeOf(IPAddress{}), ScannerFunc(ScanIPAddress), KindIPAddress)
	MustRegisterStringMapping(reflect.TypeOf(Domain{}), NonEmptyScanner(KindDomainName), KindDomainName)
	MustRegisterStringMapping(reflect.TypeOf(SHA1{}), NonEmptyScanner(KindSHA1Hash), KindSHA1Hash)
	MustRegisterStringMapping(reflect.TypeOf(SHA256{}), NonEmptyScanner(KindSHA256Hash), KindSHA256Hash)
	MustRegisterStringMapping(reflect.TypeOf(MD5{}), NonEmptyScanner(KindMD5Hash), KindMD5Hash)
	MustRegisterStringMapping(reflect.TypeOf(Hostname{}), ScannerFunc(ScanHostname), KindIPAddress, KindDomainName)
	MustRegisterStringMapping(reflect.TypeOf(URL{}), ScannerFunc(ScanURL), KindIPAddress, KindDomainName)
	MustRegisterStringMapping(reflect.TypeOf(TraceID{}), NonEmptyScanner(KindTraceID), KindTraceID)
}
