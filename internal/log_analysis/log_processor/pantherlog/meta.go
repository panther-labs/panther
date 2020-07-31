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
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/fatih/structtag"
	"github.com/pkg/errors"
)

// FieldID is the id of a field added by Panther.
// This includes both core fields that are common to all events and 'any' fields that are added on a per-logtype basis.
type FieldID int

// Core field ids (<=0)
// All core fields ids are negative integers to distinguish them.
const (
	FieldNone FieldID = 0 - iota
	CoreFieldEventTime
	CoreFieldParseTime
	CoreFieldLogType
	CoreFieldRowID
)

func coreField(id FieldID) reflect.StructField {
	return typCoreFields.Field(-1 - (int(id)))
}

// Common fields (>0)
// These fields collect string values from the log event.
// Each logtype can choose the fields it requires.
// Modules can register new fields at init() using RegisterField
const (
	FieldIPAddress FieldID = 1 + iota
	FieldDomainName
	FieldMD5Hash
	FieldSHA1Hash
	FieldSHA256Hash
	FieldTraceID
)

// CoreFields are the 'core' fields Panther adds to each log.
// External modules cannot add core fields.
type CoreFields struct {
	PantherEventTime time.Time `json:"p_event_time" validate:"required" description:"Panther added standardized event time (UTC)"`
	PantherParseTime time.Time `json:"p_parse_time" validate:"required" description:"Panther added standardized log parse time (UTC)"`
	PantherLogType   string    `json:"p_log_type" validate:"required" description:"Panther added field with type of log"`
	PantherRowID     string    `json:"p_row_id" validate:"required" description:"Panther added field with unique id (within table)"`
}

const (
	// FieldPrefixJSON is the prefix for field names injected by panther to log events.
	FieldPrefixJSON    = "p_"
	FieldPrefix        = "Panther"
	FieldLogTypeJSON   = FieldPrefixJSON + "log_type"
	FieldRowIDJSON     = FieldPrefixJSON + "row_id"
	FieldEventTimeJSON = FieldPrefixJSON + "event_time"
	FieldParseTimeJSON = FieldPrefixJSON + "parse_time"
)

var (
	typCoreFields  = reflect.TypeOf(CoreFields{})
	typStringSlice = reflect.TypeOf([]string(nil))
	// Registered fields holds the distinct index of field ids to struct fields
	registeredFields = map[FieldID]reflect.StructField{
		// Reserve ids for core fields
		CoreFieldEventTime: coreField(CoreFieldEventTime),
		CoreFieldParseTime: coreField(CoreFieldParseTime),
		CoreFieldRowID:     coreField(CoreFieldRowID),
		CoreFieldLogType:   coreField(CoreFieldLogType),
	}
	// fieldNamesJSON stores the JSON field names of registered field ids.
	fieldNamesJSON = map[FieldID]string{}
	// fieldsByName maps field names to ids to ensure field names are distinct in both Go structs and JSON objects.
	fieldsByName = map[string]FieldID{
		// Reserve field name for embedded event
		"PantherEvent": FieldNone,
		// Reserve all field names for core fields
		FieldEventTimeJSON: FieldNone,
		"PantherEventTime": FieldNone,
		FieldParseTimeJSON: FieldNone,
		"PantherParseTime": FieldNone,
		FieldLogTypeJSON:   FieldNone,
		"PantherLogType":   FieldNone,
		FieldRowIDJSON:     FieldNone,
		"PantherRowID":     FieldNone,
	}
)

func FieldNameJSON(kind FieldID) string {
	return fieldNamesJSON[kind]
}

func init() {
	MustRegisterField(FieldIPAddress, FieldMeta{
		Name:        "PantherAnyIPAddresses",
		NameJSON:    "p_any_ip_addresses",
		Description: "Panther added field with collection of ip addresses associated with the row",
	})
	MustRegisterField(FieldDomainName, FieldMeta{
		Name:        "PantherAnyDomainNames",
		NameJSON:    "p_any_domain_names",
		Description: "Panther added field with collection of domain names associated with the row",
	})
	MustRegisterField(FieldSHA1Hash, FieldMeta{
		Name:        "PantherAnySHA1Hashes",
		NameJSON:    "p_any_sha1_hashes",
		Description: "Panther added field with collection of SHA1 hashes associated with the row",
	})
	MustRegisterField(FieldSHA256Hash, FieldMeta{
		Name:        "PantherAnySHA256Hashes",
		NameJSON:    "p_any_sha256_hashes",
		Description: "Panther added field with collection of MD5 hashes associated with the row",
	})
	MustRegisterField(FieldMD5Hash, FieldMeta{
		Name:        "PantherAnyMD5Hashes",
		NameJSON:    "p_any_md5_hashes",
		Description: "Panther added field with collection of SHA256 hashes of any algorithm associated with the row",
	})
	MustRegisterField(FieldTraceID, FieldMeta{
		Name:        "PantherAnyTraceIDs",
		NameJSON:    "p_any_trace_ids",
		Description: "Panther added field with collection of context trace identifiers",
	})
	MustRegisterScanner("ip", ScannerFunc(ScanIPAddress), FieldIPAddress)
	MustRegisterScanner("domain", FieldDomainName, FieldDomainName)
	MustRegisterScanner("md5", FieldMD5Hash, FieldMD5Hash)
	MustRegisterScanner("sha1", FieldSHA1Hash, FieldSHA1Hash)
	MustRegisterScanner("sha256", FieldSHA256Hash, FieldSHA256Hash)
	MustRegisterScanner("hostname", ScannerFunc(ScanHostname), FieldDomainName, FieldIPAddress)
	MustRegisterScanner("url", ScannerFunc(ScanURL), FieldDomainName, FieldIPAddress)
	MustRegisterScanner("trace_id", FieldTraceID, FieldTraceID)
}

func MustRegisterField(kind FieldID, field FieldMeta) {
	if err := RegisterField(kind, field); err != nil {
		panic(err)
	}
}

// RegisterField allows modules to define their own field ids for 'any' fields.
// WARNING: This function is not concurrent safe and it *must* be used during `init()`
// These fields are always added as `[]string` and values can be collected can by ValueScanners using `RegisterScanner`.
func RegisterField(id FieldID, field FieldMeta) error {
	if id <= FieldNone {
		return errors.New(`invalid field id`)
	}
	if !strings.HasPrefix(field.Name, FieldPrefix) {
		return errors.Errorf(`invalid field name %q`, field.Name)
	}
	if !strings.HasPrefix(field.NameJSON, FieldPrefixJSON) {
		return errors.Errorf(`invalid field name JSON %q`, field.NameJSON)
	}
	if _, duplicate := registeredFields[id]; duplicate {
		return errors.Errorf(`duplicate field id %d`, id)
	}
	if _, duplicateFieldName := fieldsByName[field.Name]; duplicateFieldName {
		return errors.Errorf(`duplicate field name %q`, field.Name)
	}
	if _, duplicateFieldNameJSON := fieldsByName[field.Name]; duplicateFieldNameJSON {
		return errors.Errorf(`duplicate JSON field name %q`, field.Name)
	}
	registeredFields[id] = field.StructField()
	fieldNamesJSON[id] = field.NameJSON
	// Store both the JSON name and the go field name
	fieldsByName[field.Name] = id
	fieldsByName[field.NameJSON] = id
	return nil
}

// DefaultFields returns the default panther 'any' fields.
// It creates a new copy so that outside packages cannot affect the defaults.
func DefaultFields() []FieldID {
	return []FieldID{
		FieldIPAddress,
		FieldDomainName,
		FieldSHA256Hash,
		FieldSHA1Hash,
		FieldMD5Hash,
		FieldTraceID,
	}
}

var defaultMetaFields = DefaultFields()

// FieldMeta describes a panther 'any' field.
type FieldMeta struct {
	Name        string
	NameJSON    string
	Description string
}

func (m *FieldMeta) StructField() reflect.StructField {
	tag := fmt.Sprintf(`json:"%s,omitempty" description:"%s"`, m.NameJSON, m.Description)
	return reflect.StructField{
		Name: m.Name,
		Tag:  reflect.StructTag(tag),
		Type: typStringSlice,
	}
}

func MustBuildEventSchema(event interface{}, fields ...FieldID) interface{} {
	schema, err := BuildEventSchema(event, fields...)
	if err != nil {
		panic(err)
	}
	return schema
}

func BuildEventSchema(event interface{}, fields ...FieldID) (interface{}, error) {
	typ := reflect.TypeOf(event)
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	eventType, err := BuildEventTypeSchema(typ, fields...)
	if err != nil {
		return nil, err
	}
	tmp := reflect.New(eventType)
	return tmp.Interface(), nil
}

func BuildEventTypeSchema(eventType reflect.Type, extras ...FieldID) (reflect.Type, error) {
	fields, err := extendStructFields(nil, eventType)
	if err != nil {
		return nil, err
	}
	fields, _ = extendStructFields(fields, reflect.TypeOf(CoreFields{}))
	sort.Slice(extras, func(i, j int) bool {
		return extras[i] < extras[j]
	})

	// Ensure distinct field ids
	distinct := map[FieldID]bool{}
	for _, id := range extras {
		if id <= 0 {
			return nil, errors.New(`invalid field id`)
		}

		field, ok := registeredFields[id]
		if !ok {
			continue
		}
		if distinct[id] {
			continue
		}
		distinct[id] = true
		field.Index = []int{len(fields)}
		fields = append(fields, field)
	}

	if err := checkDistinctNames(fields); err != nil {
		return nil, err
	}

	if err := checkDistinctNamesJSON(fields); err != nil {
		return nil, err
	}

	return reflect.StructOf(fields), nil
}

func extendStructFields(fields []reflect.StructField, typ reflect.Type) ([]reflect.StructField, error) {
	if typ.Kind() != reflect.Struct {
		return fields, errors.New(`invalid value type`)
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		field.Index = []int{len(fields)}
		fields = append(fields, field)
	}
	return fields, nil
}

func checkDistinctNames(fields []reflect.StructField) error {
	distinct := map[string]bool{}
	for _, field := range fields {
		if distinct[field.Name] {
			return errors.Errorf(`duplicate field name %q`, field.Name)
		}
		distinct[field.Name] = true
	}
	return nil
}

func checkDistinctNamesJSON(fields []reflect.StructField) error {
	distinct := map[string]bool{}
	for _, field := range fields {
		tags, err := structtag.Parse(string(field.Tag))
		if err != nil {
			return err
		}
		jsonTag, err := tags.Get(`json`)
		if err != nil {
			return err
		}
		name := jsonTag.Name

		if distinct[name] {
			return errors.Errorf(`duplicate field name %q`, name)
		}
		distinct[name] = true
	}
	return nil
}
