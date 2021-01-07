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
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/net/idna"
)

// ValueScanner parses values from a string and writes them to a ValueWriter.
// Implementations should parse `input` and write valid values to `w`.
// If errors occur while parsing `input` no values should be written to `w`.
type ValueScanner interface {
	// ScanValues scans `input` and writes values to `w`
	ScanValues(w ValueWriter, input string)
}

// ValueScannerFunc is a function implementing ValueScanner interface
type ValueScannerFunc func(dest ValueWriter, value string)

var _ ValueScanner = (ValueScannerFunc)(nil)

// ScanValues implements ValueScanner interface
func (f ValueScannerFunc) ScanValues(dest ValueWriter, value string) {
	f(dest, value)
}

var registeredScanners = map[string]*scannerEntry{}

type scannerEntry struct {
	Scanner ValueScanner
	Fields  []FieldID
}

// MustRegisterScanner registers a value scanner to be used on string fields with a `panther` struct tag.
// It panics in case of a registration error.
func MustRegisterScanner(name string, scanner ValueScanner, fields ...FieldID) {
	if err := RegisterScanner(name, scanner, fields...); err != nil {
		panic(err)
	}
}

// MustRegisterScannerFunc registers a value scanner to be used on string fields with a `panther` struct tag.
// It panics in case of a registration error.
func MustRegisterScannerFunc(name string, scanner ValueScannerFunc, fields ...FieldID) {
	if err := RegisterScanner(name, scanner, fields...); err != nil {
		panic(err)
	}
}

// RegisterScanner tries to register a value scanner to be used on string fields with a `panther` struct tag.
// Scanner names should be unique and field ids should already be registered with `RegisterField`.
// Argument `name` defines the name to use for this scanner (ie "foo" will be used for tags with `panther:"foo").
// Argument `scanner` is the actual scanner being registered.
// Argument `fields` defines all the possible field ids this scanner can produce values for.
func RegisterScanner(name string, scanner ValueScanner, fields ...FieldID) error {
	if name == "" {
		return errors.New("anonymous scanner")
	}
	if scanner == nil {
		return errors.New("nil scanner")
	}
	if err := checkFields(fields); err != nil {
		return err
	}
	if _, duplicate := registeredScanners[name]; duplicate {
		return errors.Errorf("duplicate scanner %q", name)
	}
	registeredScanners[name] = &scannerEntry{
		Scanner: scanner,
		Fields:  fields,
	}
	return nil
}

func checkFields(fields []FieldID) error {
	if len(fields) == 0 {
		return errors.New("no value fields")
	}
	for _, id := range fields {
		if id.IsCore() {
			return errors.New("invalid field id")
		}
		if _, ok := registeredFields[id]; !ok {
			return errors.New("unregistered field id")
		}
	}
	return nil
}

// LookupScanner finds a registered scanner and field ids by name.
func LookupScanner(name string) (scanner ValueScanner, fields []FieldID) {
	if entry, ok := registeredScanners[name]; ok {
		scanner = entry.Scanner
		fields = append(fields, entry.Fields...)
	}
	return
}

// ScanURL scans a URL string for domain or ip address
func ScanURL(dest ValueWriter, input string) {
	input = strings.TrimSpace(input)
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
	input = strings.TrimSpace(input)
	if checkIPAddress(input) {
		w.WriteValues(FieldIPAddress, input)
	} else if input != "" {
		ScanDomainName(w, input)
	}
}

// ScanIPAddress scans `input` for an ip address value.
func ScanIPAddress(w ValueWriter, input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}
	if checkIPAddress(input) {
		w.WriteValues(FieldIPAddress, input)
	}
}

// ScanDomainName scans `input` domain name value, if internationalized then decodes
func ScanDomainName(w ValueWriter, input string) {
	input = strings.TrimSpace(input)
	if input != "" {
		w.WriteValues(FieldDomainName, decodePunycode(input))
	}
}

var punycodeDecoder = idna.New()

func decodePunycode(s string) string {
	if strings.HasPrefix(s, "xn--") { // puny code?
		decoded, err := punycodeDecoder.ToUnicode(s)
		if err == nil {
			s = decoded
		}
	}
	return s
}

// checkIPAddress checks if an IP address is valid
// TODO: [performance] Use a simpler method to check ip addresses than net.ParseIP to avoid allocations.
func checkIPAddress(addr string) bool {
	return net.ParseIP(addr) != nil
}

// Tries to split host:port address or falls back to Hostname scanning if `:` is not present in input
func ScanNetworkAddress(w ValueWriter, input string) {
	if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
	}
	ScanHostname(w, input)
}

// MultiScanner scans a value with multiple scanners
func MultiScanner(scanners ...ValueScanner) ValueScanner {
	switch len(scanners) {
	case 0:
		return nil
	case 1:
		return scanners[0]
	default:
		return multiScanner(scanners)
	}
}

type multiScanner []ValueScanner

func (m multiScanner) ScanValues(w ValueWriter, input string) {
	for _, scanner := range m {
		scanner.ScanValues(w, input)
	}
}

func ScanEmail(w ValueWriter, input string) {
	if pos := strings.IndexByte(input, '@'); pos != -1 {
		input = strings.TrimSpace(input)
		w.WriteValues(FieldEmail, input)
	}
}

func ScanMD5Hash(w ValueWriter, input string) {
	input = strings.TrimSpace(input)
	if len(input) == 32 && isHex(input) {
		w.WriteValues(FieldMD5Hash, strings.ToLower(input)) // normalize to lowercase
	}
}

func ScanSHA1Hash(w ValueWriter, input string) {
	input = strings.TrimSpace(input)
	if len(input) == 40 && isHex(input) {
		w.WriteValues(FieldSHA1Hash, strings.ToLower(input)) // normalize to lowercase
	}
}

func ScanSHA256Hash(w ValueWriter, input string) {
	input = strings.TrimSpace(input)
	if len(input) == 64 && isHex(input) {
		w.WriteValues(FieldSHA256Hash, strings.ToLower(input)) // normalize to lowercase
	}
}

func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; 0 <= i && i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// this function gets inlined by the compiler
// we use  a function to make the check in the loop above more readable
func isHexDigit(c byte) bool {
	return ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f') || ('0' <= c && c <= '9')
}
