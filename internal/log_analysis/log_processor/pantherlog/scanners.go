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
	"github.com/pkg/errors"
	"net"
	"net/url"
	"strings"
)

func init() {
	MustRegisterScanner("ip", ScannerFunc(ScanIPAddress), KindIPAddress)
	MustRegisterScanner("domain", KindDomainName, KindDomainName)
	MustRegisterScanner("md5", KindMD5Hash, KindMD5Hash)
	MustRegisterScanner("sha1", KindSHA1Hash, KindSHA1Hash)
	MustRegisterScanner("sha256", KindSHA256Hash, KindSHA256Hash)
	MustRegisterScanner("hostname", ScannerFunc(ScanHostname), KindDomainName, KindIPAddress)
	MustRegisterScanner("url", ScannerFunc(ScanURL), KindDomainName, KindIPAddress)
	MustRegisterScanner("trace_id", KindTraceID, KindTraceID)
}

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
