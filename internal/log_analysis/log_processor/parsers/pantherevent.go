package parsers

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"
)

type PantherFieldKind int

const (
	_ PantherFieldKind = iota
	KindIPAddress
	KindDomainName
	KindMD5Hash
	KindSHA1Hash
)

type PantherField struct {
	Kind  PantherFieldKind
	Value string
}

func SHA1Hash(hash string) PantherField {
	return PantherField{
		Kind:  KindSHA1Hash,
		Value: hash,
	}
}
func MD5Hash(hash string) PantherField {
	return PantherField{
		Kind:  KindMD5Hash,
		Value: hash,
	}
}
func DomainName(name string) PantherField {
	return PantherField{
		Kind:  KindDomainName,
		Value: name,
	}
}
func IPAddress(addr string) PantherField {
	return PantherField{
		Kind:  KindIPAddress,
		Value: addr,
	}
}

func (kind PantherFieldKind) Field(value string) PantherField {
	return PantherField{
		Kind:  kind,
		Value: value,
	}
}

type PantherEvent struct {
	LogType   string
	Timestamp time.Time
	Fields    []PantherField
}

type PantherEventer interface {
	PantherEvent() *PantherEvent
}

// Sort sorts the event Fields by kind, value ascending order
func (event *PantherEvent) Sort() {
	sort.SliceStable(event.Fields, func(i, j int) bool {
		a := &event.Fields[i]
		b := &event.Fields[j]
		if a.Kind == b.Kind {
			return a.Value < b.Value
		}
		return a.Kind < b.Kind
	})

}
func (event *PantherEvent) AppendIP(addr string) {
	if net.ParseIP(addr) != nil {
		event.Fields = append(event.Fields, KindIPAddress.Field(addr))
	}
}
func (event *PantherEvent) AppendDomain(name string) {
	event.Fields = append(event.Fields, KindDomainName.Field(name))
}
func (event *PantherEvent) Append(kind PantherFieldKind, values ...string) {
	for _, value := range values {
		event.Fields = append(event.Fields, kind.Field(value))
	}
}

// AppendP appends a fields from pointer string values
// It skips nil values.
func (event *PantherEvent) AppendP(kind PantherFieldKind, values ...*string) {
	for _, value := range values {
		if value != nil {
			event.Fields = append(event.Fields, kind.Field(*value))
		}
	}
}

func (event *PantherEvent) AppendDomainOrIP(value string) {
	if net.ParseIP(value) == nil {
		event.Fields = append(event.Fields, KindDomainName.Field(value))
	} else {
		event.Fields = append(event.Fields, KindIPAddress.Field(value))
	}
}

func NewEvent(logType string, tm time.Time, fields ...PantherField) *PantherEvent {
	return &PantherEvent{
		LogType:   logType,
		Timestamp: tm,
		Fields:    fields,
	}
}

var pantherLogRegistry = map[string]PantherLogFactory{}

// RegisterPantherLogPrefix registers custom panther log types for a log type prefix
//
// The function is *not* thread safe and it's meant to be called in an `init()` block
func RegisterPantherLogPrefix(name string, factory PantherLogFactory) {
	if _, duplicate := pantherLogRegistry[name]; duplicate {
		panic("pantherlog already registered")
	}
	pantherLogRegistry[name] = factory
}

func init() {
	RegisterPantherLogPrefix("default", func(typ string, tm time.Time, fields ...PantherField) interface{} {
		return NewPantherLog(typ, tm, fields...)
	})
}

// PantherLogFactory creates a serializable struct from a PantherEvent
type PantherLogFactory func(logType string, tm time.Time, fields ...PantherField) interface{}

func LogTypePrefix(logType string) string {
	if pos := strings.IndexByte(logType, '.'); 0 <= pos && pos < len(logType) {
		return logType[:pos]
	}
	return ""
}

func ComposeStruct(values ...interface{}) (reflect.Value, error) {
	fields := make([]reflect.StructField, 0, len(values))
	fieldValues := make([]reflect.Value, 0, len(values))
	for _, x := range values {
		if x == nil {
			continue
		}
		value := reflect.Indirect(reflect.ValueOf(x))
		typ := value.Type()
		if typ.Kind() != reflect.Struct {
			continue
		}
		name := typ.Name()
		for i := range fields {
			if fields[i].Name == name {
				return reflect.Value{}, fmt.Errorf("Failed to compose struct: Multiple fields of type %s", typ)
			}
		}
		fieldValues = append(fieldValues, value)
		fields = append(fields, reflect.StructField{
			Anonymous: true,
			Index:     []int{len(fields)},
			Name:      name,
			Type:      typ,
		})
	}
	dynType := reflect.StructOf(fields)
	dynValue := reflect.New(dynType)
	for i, value := range fieldValues {
		dynValue.Elem().Field(i).Set(value)
	}
	return dynValue, nil
}
