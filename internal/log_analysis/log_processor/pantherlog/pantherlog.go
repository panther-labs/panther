// Package pantherlog defines types and functions to parse logs for Panther
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
	"reflect"
	"time"

	"github.com/modern-go/reflect2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

type Event interface {
	PantherLogEvent() (string, *time.Time)
}

func EventStruct(event Event) interface{} {
	return defaultMetaFields.EventStruct(event)
}

// Index of special string types that extract pantherlog Values during JSON encoding.
// These types use a decoder that scans the decoded string value with a ValueScanner to extract pantherlog values
// in a single pass while decoding input JSON.
// To achieve that they check the iterator instance for a `*ValueBuffer` attachment and use it in the `ScanValues`
// method of their respective ValueScanner.
// Each entry in this index also contains a list of *all* possible `ValueKind` values that the scanner can produce.
// This information can be retrieved with the RegisteredValueKinds() package method.

func RegisteredValueKinds(typ reflect.Type) (kinds []ValueKind) {
	typ2 := reflect2.Type2(typ)
	return registeredTypes[typ2]
}

func init() {
	null.MustRegisterString(
		&IPAddress{},
		&Domain{},
		&SHA1{},
		&SHA256{},
		&MD5{},
		&Hostname{},
		&TraceID{},
		&URL{},
	)
	MustRegisterCustomEncoder(&IPAddress{}, KindIPAddress)
	MustRegisterCustomEncoder(&Domain{}, KindDomainName)
	MustRegisterCustomEncoder(&SHA1{}, KindSHA1Hash)
	MustRegisterCustomEncoder(&SHA256{}, KindSHA256Hash)
	MustRegisterCustomEncoder(&MD5{}, KindMD5Hash)
	MustRegisterCustomEncoder(&Hostname{}, KindIPAddress, KindDomainName)
	MustRegisterCustomEncoder(&URL{}, KindIPAddress, KindDomainName)
	MustRegisterCustomEncoder(&TraceID{}, KindTraceID)
}
