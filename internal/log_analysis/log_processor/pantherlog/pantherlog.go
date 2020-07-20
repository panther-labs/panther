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
	"time"
)

type Event interface {
	PantherLogEvent() (string, *time.Time)
}

func EventStruct(event Event) interface{} {
	return defaultMetaFields.EventStruct(event)
}

// TagName is used for defining value scan methods on string fields.
const TagName = "panther"

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

// Index of special string types that extract pantherlog Values during JSON encoding.
// These types use a decoder that scans the decoded string value with a ValueScanner to extract pantherlog values
// in a single pass while decoding input JSON.
// To achieve that they check the iterator instance for a `*ValueBuffer` attachment and use it in the `ScanValues`
// method of their respective ValueScanner.
// Each entry in this index also contains a list of *all* possible `ValueKind` values that the scanner can produce.
// This information can be retrieved with the RegisteredValueKinds() package method.

//func RegisteredScannerKinds(typ reflect.Type) (kinds []ValueKind) {
//	typ2 := reflect2.Type2(typ)
//	return registeredTypes[typ2]
//}
//
//func init() {
//	null.MustRegisterString(
//		&IPAddress{},
//		&Domain{},
//		&SHA1{},
//		&SHA256{},
//		&MD5{},
//		&Hostname{},
//		&TraceID{},
//		&URL{},
//	)
//	MustRegisterCustomEncoder(&IPAddress{}, KindIPAddress)
//	MustRegisterCustomEncoder(&Domain{}, KindDomainName)
//	MustRegisterCustomEncoder(&SHA1{}, KindSHA1Hash)
//	MustRegisterCustomEncoder(&SHA256{}, KindSHA256Hash)
//	MustRegisterCustomEncoder(&MD5{}, KindMD5Hash)
//	MustRegisterCustomEncoder(&Hostname{}, KindIPAddress, KindDomainName)
//	MustRegisterCustomEncoder(&URL{}, KindIPAddress, KindDomainName)
//	MustRegisterCustomEncoder(&TraceID{}, KindTraceID)
//}

//func canCastUnsafe(from ,to reflect.Type) bool {
//	if from.ConvertibleTo(to) {
//		return true
//	}
//	if from.Kind() == reflect.Struct && from.NumField() == 1 {
//		field := from.Field(0)
//		return field.Anonymous && field.Type.ConvertibleTo(to)
//	}
//	return false
//
//}

//func MustRegisterCustomEncoder(f ValueWriterTo, kinds ...ValueKind) {
//	if err := RegisterCustomEncoder(f, kinds...); err != nil {
//		panic(err)
//	}
//}

//func RegisterCustomEncoder(f ValueWriterTo, kinds ...ValueKind) error {
//	if f == nil {
//		return errors.New(`nil field`)
//	}
//	if err := checkKinds(kinds); err != nil {
//		return err
//	}
//	val := reflect.ValueOf(f)
//	typ := val.Elem().Type()
//	typ = derefType(typ)
//	typName := typ.String()
//	if typName == "" {
//		return errors.New("anonymous type")
//	}
//	typ2 := reflect2.Type2(typ)
//	if _, duplicate := registeredTypes[typ2]; duplicate {
//		return errors.New("duplicate scanner mapping")
//	}
//	registeredTypes[typ2] = kinds
//	return nil
//}
