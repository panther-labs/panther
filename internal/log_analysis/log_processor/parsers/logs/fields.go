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
)

type Field struct {
	Kind  FieldKind
	Value string
}

func (f Field) IsZero() bool {
	return f == Field{}
}

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

type FieldBuffer struct {
	Fields map[FieldKind]sort.StringSlice
}

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
// Usefull for tests.
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

func (b *FieldBuffer) Reset() {
	for kind, values := range b.Fields {
		b.Fields[kind] = values[:0]
	}
}

// ValuesUnsorted returns unsorted field values
func (b *FieldBuffer) ValuesUnsorted(kind FieldKind) []string {
	return b.Fields[kind]
}

// Values returns field values sorted
func (b *FieldBuffer) Values(kind FieldKind) []string {
	values := b.Fields[kind]
	if len(values) > 1 {
		sort.Sort(values)
	}
	return values
}

// func (b *FieldBuffer) WriteJSON(stream *jsoniter.Stream) error {
// 	if b == nil {
// 		stream.WriteNil()
// 		return nil
// 	}
// 	if len(b.Fields) == 0 {
// 		stream.WriteEmptyObject()
// 		return nil
// 	}
// 	stream.WriteObjectStart()
// 	n := 0
// 	for kind, values := range b.Fields {
// 		if len(values) == 0 {
// 			continue
// 		}
// 		fieldName := fieldRegistry[kind].FieldNameJSON
// 		if fieldName == "" {
// 			continue
// 		}
// 		values = sort.StringSlice(values)
// 		if n > 0 {
// 			stream.WriteMore()
// 		}
// 		n++
// 		stream.WriteObjectField(fieldName)
// 		stream.WriteArrayStart()
// 		for i, value := range values {
// 			if i != 0 {
// 				stream.WriteMore()
// 			}
// 			stream.WriteString(value)
// 		}
// 		stream.WriteArrayEnd()
// 	}
// 	stream.WriteObjectEnd()
// 	return nil
// }

type FieldFactory func(string) Field

type FieldEntry struct {
	Name          string
	NewField      FieldFactory
	FieldNameJSON string
}

var fieldRegistry = map[FieldKind]FieldEntry{
	KindIPAddress: {
		Name:          "ip_address",
		FieldNameJSON: "p_any_ip_addresses",
		NewField:      IPAddress,
	},
	KindDomainName: {
		Name:          "domain",
		FieldNameJSON: "p_any_domain_names",
		NewField:      DomainName,
	},
	KindHostname: {
		Name:          "hostname",
		FieldNameJSON: "-",
		NewField:      Hostname,
	},
	KindMD5Hash: {
		Name:          "md5",
		FieldNameJSON: "p_any_md5_hashes",
		NewField:      MD5Hash,
	},
	KindSHA1Hash: {
		Name:          "sha1",
		FieldNameJSON: "p_any_sha1_hashes",
		NewField:      SHA1Hash,
	},
	KindSHA256Hash: {
		Name:          "sha256",
		FieldNameJSON: "p_any_sha256_hashes",
		NewField:      SHA256Hash,
	},
}

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

func (kind FieldKind) String() string {
	switch kind {
	case KindIPAddress:
		return "ip_address"
	case KindMD5Hash:
		return "md5"
	case KindSHA1Hash:
		return "sha1"
	case KindDomainName:
		return "domain"
	case KindHostname:
		return "hostname"
	default:
		return ""
	}
}

var _ FieldExtractor = (FieldKind)(0)

func (kind FieldKind) ExtractFields(value string, fields *FieldBuffer) error {
	field := Field{Kind: kind, Value: value}
	if field.IsZero() {
		return nil
	}
	fields.Add(field)
	return nil
}

// func (kind FieldKind) Field(value string) Field {
// 	if entry, ok := fieldRegistry[kind]; ok {
// 		return entry.NewField(value)
// 	}
// 	value = strings.TrimSpace(value)
// 	return Field{
// 		Kind:  kind,
// 		Value: value,
// 	}
// }

// CheckIPAddress checks if an IP address is valid
func checkIPAddress(addr string) bool {
	return net.ParseIP(addr) != nil
}

func IPAddress(addr string) Field {
	addr = strings.TrimSpace(addr)
	if checkIPAddress(addr) {
		return Field{KindIPAddress, addr}
	}
	return Field{}
}
func IPAddressP(addr *string) Field {
	if addr != nil {
		return IPAddress(*addr)
	}
	return Field{}
}

// SHA1Hash packs an SHA1 hash value to a PantherField
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

// MD5Hash packs an MD5 hash value to a PantherField
func MD5Hash(hash string) Field {
	return Field{
		Kind:  KindMD5Hash,
		Value: hash,
	}

}

// MD5HashP packs an MD5 hash pointer value to a PantherField
func MD5HashP(hash *string) Field {
	if hash != nil {
		return MD5Hash(*hash)
	}
	return Field{}
}

// SHA256Hash packs an SHA356 hash value to a PantherField
func SHA256Hash(hash string) Field {
	return Field{
		Kind:  KindSHA256Hash,
		Value: hash,
	}

}

func SHA256HashP(hash *string) Field {
	if hash != nil {
		return SHA256Hash(*hash)
	}
	return Field{}
}

// DomainName packs a domain name value to a PantherField
func DomainName(name string) Field {
	return Field{
		Value: name,
		Kind:  KindDomainName,
	}
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

// type SmallStringSet struct {
// 	Values []string
// }

// func (set *SmallStringSet) Reset() {
// 	set.Values = set.Values[:0]
// }

// func (set *SmallStringSet) MarshalJSON() ([]byte, error) {
// 	sort.Strings(set.Values)
// 	return jsoniter.Marshal(([]string)(set.Values))
// }

// func (set *SmallStringSet) Contains(value string) bool {
// 	for _, s := range set.Values {
// 		if s == value {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (set *SmallStringSet) Insert(value string) {
// 	if value == "" {
// 		return
// 	}
// 	for _, v := range set.Values {
// 		if v == value {
// 			return
// 		}
// 	}
// 	set.Values = append(set.Values, value)
// }
