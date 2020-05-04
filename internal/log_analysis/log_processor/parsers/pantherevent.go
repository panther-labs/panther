package parsers

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

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"

// PantherEventer is the interface to be implemented by all parsed log events.
type PantherEventer interface {
	PantherEvent() *logs.Event
}

// // ComposeStruct composes values into a single reflect struct that serializes using fields from all values as top-level
// // It requires all `values` to be struct or struct pointers and be of distinct type.
// func ComposeStruct(values ...interface{}) (reflect.Value, error) {
// 	fields := make([]reflect.StructField, 0, len(values))
// 	fieldValues := make([]reflect.Value, 0, len(values))
// 	for _, x := range values {
// 		if x == nil {
// 			continue
// 		}
// 		value := reflect.Indirect(reflect.ValueOf(x))
// 		typ := value.Type()
// 		if typ.Kind() != reflect.Struct {
// 			continue
// 		}
// 		name := typ.Name()
// 		for i := range fields {
// 			if fields[i].Name == name {
// 				return reflect.Value{}, errors.Errorf("failed to compose struct: Multiple fields of type %s", typ)
// 			}
// 		}
// 		fieldValues = append(fieldValues, value)
// 		fields = append(fields, reflect.StructField{
// 			Anonymous: true,
// 			Index:     []int{len(fields)},
// 			Name:      name,
// 			Type:      typ,
// 		})
// 	}
// 	dynType := reflect.StructOf(fields)
// 	dynValue := reflect.New(dynType)
// 	for i, value := range fieldValues {
// 		dynValue.Elem().Field(i).Set(value)
// 	}
// 	return dynValue, nil
// }

// // Panther event is the minimal info required to build a panther log event.
// // LogType determines the type of `PantherLog` to be produced by this event.
// // Fields can be extracted from any log source and will be used to populate the `PantherLog` instance.
// type PantherEvent struct {
// 	LogType   string
// 	Timestamp time.Time
// 	Fields    []PantherField
// }

// var _ sort.Interface = (*PantherEvent)(nil)

// // Len implements sort.Interface
// func (event *PantherEvent) Len() int {
// 	return len(event.Fields)
// }

// // Swap implements sort.Interface
// func (event *PantherEvent) Swap(i, j int) {
// 	event.Fields[i], event.Fields[j] = event.Fields[j], event.Fields[i]
// }

// // Less implements sort.Interface
// func (event *PantherEvent) Less(i, j int) bool {
// 	a := &event.Fields[i]
// 	b := &event.Fields[j]
// 	if a.Kind == b.Kind {
// 		return a.Value < b.Value
// 	}
// 	return a.Kind < b.Kind
// }

// func (event *PantherEvent) Extend(fields ...PantherField) {
// 	for i := range fields {
// 		event.InsertP(&fields[i])
// 	}
// }
// func (event *PantherEvent) Insert(field PantherField) {
// 	event.InsertP(&field)
// }

// func (event *PantherEvent) InsertP(field *PantherField) {
// 	if field.IsEmpty() || event.Contains(field) {
// 		return
// 	}
// 	event.Fields = append(event.Fields, *field)
// }

// func (event *PantherEvent) Contains(field *PantherField) bool {
// 	for i := range event.Fields {
// 		f := &event.Fields[i]
// 		if f.Kind == field.Kind && f.Value == field.Value {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (event *PantherEvent) Append(kind PantherFieldKind, values ...string) {
// 	for _, value := range values {
// 		event.Extend(kind.Field(value))
// 	}
// }

// // NewEvent creates a new panther event.
// func NewEvent(logType string, tm time.Time, fields ...PantherField) *PantherEvent {
// 	event := &PantherEvent{
// 		LogType:   logType,
// 		Timestamp: tm.UTC(),
// 		Fields:    make([]PantherField, 0, len(fields)),
// 	}
// 	event.Extend(fields...)
// 	return event
// }

// func LogTypePrefix(logType string) string {
// 	if pos := strings.IndexByte(logType, '.'); 0 <= pos && pos < len(logType) {
// 		return logType[:pos]
// 	}
// 	return ""
// }

// type PantherFieldKind int

// const (
// 	KindNone PantherFieldKind = iota
// 	KindIPAddress
// 	KindDomainName
// 	KindMD5Hash
// 	KindSHA1Hash
// 	KindHostname // Resolves to IPAddress or DomainName
// )

// func (kind PantherFieldKind) String() string {
// 	switch kind {
// 	case KindIPAddress:
// 		return "ip_address"
// 	case KindMD5Hash:
// 		return "md5"
// 	case KindSHA1Hash:
// 		return "sha1"
// 	case KindDomainName:
// 		return "domain"
// 	case KindHostname:
// 		return "hostname"
// 	default:
// 		return ""
// 	}
// }

// type PantherFieldFactory func(string) PantherField

// func (kind PantherFieldKind) defaultFactory() PantherFieldFactory {
// 	return func(value string) PantherField {
// 		if value = strings.TrimSpace(value); value != "" {
// 			return PantherField{
// 				Kind:  kind,
// 				Value: value,
// 			}
// 		}
// 		return PantherField{}
// 	}
// }

// func zeroPantherField(_ string) PantherField {
// 	return PantherField{}
// }

// // pantherFieldRegistry is a registry of known panther fields.
// // Lookup on a map with int keys is very efficient.
// // For max efficiency use the factories directly.
// var pantherFieldRegistry = map[PantherFieldKind]PantherFieldFactory{
// 	KindNone:       zeroPantherField,
// 	KindIPAddress:  IPAddress,
// 	KindMD5Hash:    MD5Hash,
// 	KindSHA1Hash:   SHA1Hash,
// 	KindDomainName: DomainName,
// 	KindHostname:   Hostname,
// }

// func RegisterPantherField(kind PantherFieldKind, factory PantherFieldFactory) {
// 	if _, duplicate := pantherFieldRegistry[kind]; duplicate {
// 		panic("duplicate panther field kind")
// 	}
// 	if factory == nil {
// 		factory = kind.defaultFactory()
// 	}
// 	pantherFieldRegistry[kind] = factory
// }

// // PantherField is a typed string value recognized by panther for querying.
// // A PantherField has a `Kind` that determines where in a PantherLog to append the field.
// type PantherField struct {
// 	Kind  PantherFieldKind
// 	Value string
// }

// func (field PantherField) IsZero() bool {
// 	return field == PantherField{}
// }
// func (field *PantherField) IsEmpty() bool {
// 	return field.Kind == KindNone || field.Value == ""
// }

// // SHA1Hash packs an SHA1 hash value to a PantherField
// func SHA1Hash(hash string) PantherField {
// 	return NewPantherField(KindSHA1Hash, hash)
// }

// func SHA1HashP(hash *string) PantherField {
// 	return NewPantherFieldP(KindSHA1Hash, hash)
// }

// // MD5Hash packs an MD5 hash value to a PantherField
// func MD5Hash(hash string) PantherField {
// 	return NewPantherField(KindMD5Hash, hash)
// }
// func MD5HashP(hash *string) PantherField {
// 	return NewPantherFieldP(KindMD5Hash, hash)
// }

// func NewPantherFieldP(kind PantherFieldKind, value *string) PantherField {
// 	if value != nil {
// 		return NewPantherField(kind, *value)
// 	}
// 	return PantherFieldZero()
// }
// func NewPantherField(kind PantherFieldKind, value string) PantherField {
// 	if value = strings.TrimSpace(value); value != "" {
// 		return PantherField{
// 			Kind:  kind,
// 			Value: value,
// 		}
// 	}
// 	return PantherFieldZero()
// }

// // DomainName packs a domain name value to a PantherField
// func DomainName(name string) PantherField {
// 	return NewPantherField(KindDomainName, name)
// }
// func DomainNameP(name *string) PantherField {
// 	return NewPantherFieldP(KindDomainName, name)
// }

// func IPAddress(addr string) PantherField {
// 	addr = strings.TrimSpace(addr)
// 	if CheckIPAddress(addr) {
// 		return PantherField{KindIPAddress, addr}
// 	}
// 	return PantherFieldZero()
// }
// func PantherFieldZero() PantherField {
// 	return PantherField{}
// }

// func IPAddressP(addr *string) PantherField {
// 	if addr != nil {
// 		return IPAddress(*addr)
// 	}
// 	return PantherFieldZero()
// }

// // Hostname returns either an IPAddress or a DomainName field
// func Hostname(value string) PantherField {
// 	if value = strings.TrimSpace(value); value != "" {
// 		if CheckIPAddress(value) {
// 			return NewPantherField(KindIPAddress, value)
// 		}
// 		return NewPantherField(KindDomainName, value)
// 	}
// 	return PantherFieldZero()
// }

// // HostnameP returns either an IPAddress or a DomainName field from a pointer
// func HostnameP(value *string) PantherField {
// 	if value != nil {
// 		return Hostname(*value)
// 	}
// 	return PantherFieldZero()
// }

// func (kind PantherFieldKind) FieldP(value *string) PantherField {
// 	if value != nil {
// 		return kind.Field(*value)
// 	}
// 	return PantherField{}
// }

// func (kind PantherFieldKind) Field(value string) PantherField {
// 	factory, ok := pantherFieldRegistry[kind]
// 	if !ok {
// 		panic(fmt.Sprintf("unregistered panther field %d %s", kind, value))
// 	}
// 	return factory(value)
// }

// func (event *PantherEvent) RemoveDuplicates() {
// 	if len(event.Fields) > 1 {
// 		sort.Sort(event)
// 		fields, last := event.Fields[:1], event.Fields[0]
// 		for _, field := range event.Fields {
// 			if field == last {
// 				continue
// 			}
// 			fields = append(fields, field)
// 			last = field
// 		}
// 		event.Fields = fields
// 	}
// }

// // CheckIPAddress checks if an IP address is valid
// func CheckIPAddress(addr string) bool {
// 	return net.ParseIP(addr) != nil
// }
