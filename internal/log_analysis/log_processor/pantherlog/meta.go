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
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

// FieldID is the id of a field added by Panther.
// This includes both core fields that are common to all events and indicator fields that are added on a per-logtype basis.
type FieldID int

// Core field ids (<=0)
// All core fields ids are negative integers to distinguish them.
const (
	FieldNone FieldID = 0 - iota
	CoreFieldEventTime
	CoreFieldParseTime
	CoreFieldLogType
	CoreFieldRowID
	CoreFieldSourceID
	CoreFieldSourceLabel
)

func coreField(id FieldID) reflect.StructField {
	return typCoreFields.Field(-1 - (int(id)))
}

// IsCore checks if a field id is core
func (id FieldID) IsCore() bool {
	return id <= 0
}

// Indicator fields (>0)
// These fields collect string values from the log event.
// Each log type can choose the indicator fields it requires.
// Modules can register new indicator fields at init() using RegisterIndicator
const (
	FieldIPAddress FieldID = 1 + iota
	FieldDomainName
	FieldMD5Hash
	FieldSHA1Hash
	FieldSHA256Hash
	FieldTraceID
	FieldAWSAccountID
	FieldAWSInstanceID
	FieldAWSARN
	FieldAWSTag
	FieldEmail
	FieldUsername
)

// ScanValues implements ValueScanner interface
func (id FieldID) ScanValues(w ValueWriter, input string) {
	w.WriteValues(id, strings.TrimSpace(input))
}

// CoreFields are the 'core' fields Panther adds to each log.
// External modules cannot add core fields.
type CoreFields struct {
	PantherEventTime   time.Time `json:"p_event_time" validate:"required" description:"Panther added standardized event time (UTC)"`
	PantherParseTime   time.Time `json:"p_parse_time" validate:"required" description:"Panther added standardized log parse time (UTC)"`
	PantherLogType     string    `json:"p_log_type" validate:"required" description:"Panther added field with type of log"`
	PantherRowID       string    `json:"p_row_id" validate:"required" description:"Panther added field with unique id (within table)"`
	PantherSourceID    string    `json:"p_source_id,omitempty" description:"Panther added field with the source id"`
	PantherSourceLabel string    `json:"p_source_label,omitempty" description:"Panther added field with the source label"`
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
		CoreFieldEventTime:   coreField(CoreFieldEventTime),
		CoreFieldParseTime:   coreField(CoreFieldParseTime),
		CoreFieldRowID:       coreField(CoreFieldRowID),
		CoreFieldLogType:     coreField(CoreFieldLogType),
		CoreFieldSourceID:    coreField(CoreFieldSourceID),
		CoreFieldSourceLabel: coreField(CoreFieldSourceLabel),
	}
	// registeredFieldNamesJSON stores the JSON field names of registered field ids.
	registeredFieldNamesJSON = map[FieldID]string{}
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

// FieldNameJSON returns the JSON field name of a field id.
func FieldNameJSON(kind FieldID) string {
	return registeredFieldNamesJSON[kind]
}

// RegisteredFieldNamesJSON returns the JSON field names for registered indicator fields
func RegisteredFieldNamesJSON() (names []string) {
	for id, name := range registeredFieldNamesJSON {
		if id.IsCore() {
			continue
		}
		names = append(names, name)
	}
	return
}

func init() {
	MustRegisterIndicator(FieldIPAddress, FieldMeta{
		Name:        "PantherAnyIPAddresses",
		NameJSON:    "p_any_ip_addresses",
		Description: "Panther added field with collection of ip addresses associated with the row",
	})
	MustRegisterIndicator(FieldDomainName, FieldMeta{
		Name:        "PantherAnyDomainNames",
		NameJSON:    "p_any_domain_names",
		Description: "Panther added field with collection of domain names associated with the row",
	})
	MustRegisterIndicator(FieldSHA1Hash, FieldMeta{
		Name:        "PantherAnySHA1Hashes",
		NameJSON:    "p_any_sha1_hashes",
		Description: "Panther added field with collection of SHA1 hashes associated with the row",
	})
	MustRegisterIndicator(FieldSHA256Hash, FieldMeta{
		Name:        "PantherAnySHA256Hashes",
		NameJSON:    "p_any_sha256_hashes",
		Description: "Panther added field with collection of MD5 hashes associated with the row",
	})
	MustRegisterIndicator(FieldMD5Hash, FieldMeta{
		Name:        "PantherAnyMD5Hashes",
		NameJSON:    "p_any_md5_hashes",
		Description: "Panther added field with collection of SHA256 hashes of any algorithm associated with the row",
	})
	MustRegisterIndicator(FieldTraceID, FieldMeta{
		Name:        "PantherAnyTraceIDs",
		NameJSON:    "p_any_trace_ids",
		Description: "Panther added field with collection of context trace identifiers",
	})
	MustRegisterIndicator(FieldAWSAccountID, FieldMeta{
		Name:        "PantherAnyAWSAccountIDs",
		NameJSON:    "p_any_aws_account_ids",
		Description: "Panther added field with collection of AWS account ids associated with the row",
	})
	MustRegisterIndicator(FieldAWSInstanceID, FieldMeta{
		Name:        "PantherAnyAWSInstanceIDs",
		NameJSON:    "p_any_aws_instance_ids",
		Description: "Panther added field with collection of AWS instance ids associated with the row",
	})
	MustRegisterIndicator(FieldAWSARN, FieldMeta{
		Name:        "PantherAnyAWSARNs",
		NameJSON:    "p_any_aws_arns",
		Description: "Panther added field with collection of AWS ARNs associated with the row",
	})
	MustRegisterIndicator(FieldAWSTag, FieldMeta{
		Name:        "PantherAnyAWSTags",
		NameJSON:    "p_any_aws_tags",
		Description: "Panther added field with collection of AWS Tags associated with the row",
	})
	MustRegisterIndicator(FieldEmail, FieldMeta{
		Name:        "PantherAnyEmails",
		NameJSON:    "p_any_emails",
		Description: "Panther added field with collection of email addresses associated with the row",
	})
	MustRegisterIndicator(FieldUsername, FieldMeta{
		Name:        "PantherAnyUsernames",
		NameJSON:    "p_any_usernames",
		Description: "Panther added field with collection of usernames associated with the row",
	})
	MustRegisterScannerFunc("ip", ScanIPAddress, FieldIPAddress)
	MustRegisterScanner("domain", FieldDomainName, FieldDomainName)
	MustRegisterScanner("md5", FieldMD5Hash, FieldMD5Hash)
	MustRegisterScanner("sha1", FieldSHA1Hash, FieldSHA1Hash)
	MustRegisterScanner("sha256", FieldSHA256Hash, FieldSHA256Hash)
	MustRegisterScannerFunc("hostname", ScanHostname, FieldDomainName, FieldIPAddress)
	MustRegisterScannerFunc("url", ScanURL, FieldDomainName, FieldIPAddress)
	MustRegisterScanner("trace_id", FieldTraceID, FieldTraceID)
	MustRegisterScannerFunc("net_addr", ScanNetworkAddress, FieldIPAddress, FieldDomainName)
	MustRegisterScannerFunc("aws_arn", ScanARN,
		FieldAWSARN,
		FieldAWSInstanceID,
		FieldAWSAccountID,
	)
	MustRegisterScannerFunc("aws_account_id", ScanAWSAccountID, FieldAWSAccountID)
	MustRegisterScannerFunc("aws_instance_id", ScanAWSInstanceID, FieldAWSInstanceID)
	MustRegisterScannerFunc("aws_tag", ScanAWSTag, FieldAWSTag)
	MustRegisterScannerFunc("email", ScanEmail, FieldEmail)
	MustRegisterScanner("username", FieldUsername, FieldUsername)
}

// MustRegisterIndicator allows modules to define their own indicator fields.
// It panics if a registration error occurs.
// WARNING: This function is not concurrent safe and it *must* be used during `init()`
func MustRegisterIndicator(id FieldID, field FieldMeta) {
	if err := RegisterIndicator(id, field); err != nil {
		panic(err)
	}
}

// RegisterIndicator allows modules to define their own indicator fields.
// WARNING: This function is not concurrent safe and it *must* be used during `init()`
// These fields are always added as `[]string` and values can be collected can by scanners using `RegisterScanner`.
func RegisterIndicator(id FieldID, field FieldMeta) error {
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
	registeredFieldNamesJSON[id] = field.NameJSON
	// Store both the JSON name and the go field name
	fieldsByName[field.Name] = id
	fieldsByName[field.NameJSON] = id
	return nil
}

// DefaultIndicators returns the default panther indicator fields.
// It creates a new copy so that outside packages cannot affect the defaults.
func DefaultIndicators() FieldSet {
	return FieldSet{
		FieldIPAddress,
		FieldDomainName,
		FieldSHA256Hash,
		FieldSHA1Hash,
		FieldMD5Hash,
		FieldTraceID,
	}
}

// FieldMeta describes a panther field.
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

// MustBuildEventSchema builds a struct that extends the fields of `event` with all the fields added by Panther.
// It automatically detects indicator field ids required for `event` if no `indicators` are passed.
// It panics if an error occurred while building the new struct
func MustBuildEventSchema(event interface{}, indicators ...FieldID) interface{} {
	schema, err := BuildEventSchema(event, indicators...)
	if err != nil {
		panic(err)
	}
	return schema
}

// BuildEventSchema builds a struct that extends the fields of `event` with all the fields added by Panther.
// It automatically detects indicator field ids required for `event` if no `indicators` are passed.
// It checks for duplicate field names in both JSON and go.
func BuildEventSchema(event interface{}, indicators ...FieldID) (interface{}, error) {
	typ := reflect.TypeOf(event)
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	eventType, err := BuildEventTypeSchema(typ, indicators...)
	if err != nil {
		return nil, err
	}
	tmp := reflect.New(eventType)
	return tmp.Interface(), nil
}

// BuildEventTypeSchema builds a struct that extends the fields of `eventType` with all the fields added by Panther.
// It automatically detects indicator field ids required for `eventType` if no `indicators` are passed.
// It checks for duplicate field names in both JSON and go.
func BuildEventTypeSchema(eventType reflect.Type, indicators ...FieldID) (reflect.Type, error) {
	fields, err := extendStructFields(nil, eventType)
	if err != nil {
		return nil, err
	}
	fields, _ = extendStructFields(fields, reflect.TypeOf(CoreFields{}))

	// Auto-detect required field ids
	if indicators == nil {
		indicators = FieldSetFromType(eventType)
	}
	indicators = NewFieldSet(indicators...).Indicators()
	// Sort field set to make sure struct fields have strict order
	sort.Sort(FieldSet(indicators))

	// Ensure distinct field ids
	distinct := map[FieldID]bool{}
	for _, id := range indicators {
		if id.IsCore() {
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
	return visitStructFieldsJSON(reflect.StructOf(fields), func(field reflect.StructField) error {
		if distinct[field.Name] {
			return errors.Errorf(`duplicate field name %q`, field.Name)
		}
		distinct[field.Name] = true
		return nil
	})
}

func checkDistinctNamesJSON(fields []reflect.StructField) error {
	distinct := map[string]bool{}
	return visitStructFieldsJSON(reflect.StructOf(fields), func(field reflect.StructField) error {
		name := resolveFieldNameJSON(&field)
		if name == "" {
			return nil
		}
		if distinct[name] {
			return errors.Errorf(`duplicate field name %q`, field.Name)
		}
		distinct[name] = true
		return nil
	})
}

func visitStructFieldsJSON(typ reflect.Type, visit func(field reflect.StructField) error) error {
	typ = derefType(typ)
	if typ.Kind() != reflect.Struct {
		return nil
	}
	numFields := typ.NumField()
	for i := 0; i < numFields; i++ {
		field := typ.Field(i)
		name := resolveFieldNameJSON(&field)
		// We only visit json visible fields and embedded fields
		switch {
		case name != "":
			if err := visit(field); err != nil {
				return err
			}
		case field.Anonymous:
			if err := visitStructFieldsJSON(field.Type, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

// helper to deref pointer types
func derefType(typ reflect.Type) reflect.Type {
	for typ != nil && typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	return typ
}

// helper to resolve the json field name of a struct field
// returns an empty string if the field is not visible in JSON
func resolveFieldNameJSON(field *reflect.StructField) string {
	if !isPublicFieldName(field.Name) {
		return ""
	}
	tags, err := structtag.Parse(string(field.Tag))
	if err != nil {
		return field.Name
	}
	const tagJSON = `json`
	jsonTag, err := tags.Get(tagJSON)
	if err != nil {
		// Field has no `json` tag. It uses it's own name as JSON field name
		return field.Name
	}
	// Handle all possible cases properly
	switch name := jsonTag.Name; name {
	case "-":
		// Foo string `json:"-"`
		return ""
	case "":
		// Foo string `json:",omitempty"`
		return field.Name
	default:
		// Foo string `json:"foo"`
		// Foo string `json:"foo,omitempty"`
		return name
	}
}

func isPublicFieldName(name string) bool {
	return strings.Title(name) == name
}

// FieldSet is a set of field ids.
// It provides helper methods to sort, filter and extend a set of uniquee fields ids.
type FieldSet []FieldID

// NewFieldSet creates a new set of distinct field ids
func NewFieldSet(ids ...FieldID) (fields FieldSet) {
	for _, id := range ids {
		fields = fields.Add(id)
	}
	return fields
}

// Add appends a field id to the set if it is not already there.
func (fields FieldSet) Add(id FieldID) FieldSet {
	for _, duplicate := range fields {
		if duplicate == id {
			return fields
		}
	}
	return append(fields, id)
}

// Extend extends the set to include ids.
func (fields FieldSet) Extend(ids ...FieldID) FieldSet {
	for _, id := range ids {
		fields = fields.Add(id)
	}
	return fields
}

// Indicators returns a copy of the set containing only indicator field ids
func (fields FieldSet) Indicators() (indicators FieldSet) {
	if fields == nil {
		return
	}
	for _, field := range fields {
		if field.IsCore() {
			continue
		}
		indicators = indicators.Add(field)
	}
	return
}

// FieldSetFromTag produces the minimum required field set to support scanners defined in a struct tag.
func FieldSetFromTag(tag string) FieldSet {
	tags, err := structtag.Parse(tag)
	if err != nil {
		return nil
	}

	// Lookup field json name to see if it is one of the registered fields
	if jsonTag, err := tags.Get(`json`); err == nil {
		if id, ok := fieldsByName[jsonTag.Name]; ok {
			return FieldSet{id}
		}
	}

	// Check the indicator tag to see if it maps to a registered scanner
	pantherTag, err := tags.Get(TagNameIndicator)
	if err != nil {
		// No `panther` tag
		return nil
	}
	_, fields := LookupScanner(pantherTag.Name)
	return fields
}

// FieldSetFromType produces the minimum required field set to support scanners and core fields defined in a struct.
func FieldSetFromType(typ reflect.Type) (fields FieldSet) {
	switch typ := derefType(typ); typ.Kind() {
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			// Anonymous struct fields can have their public fields exposed to JSON
			if field.Anonymous || isPublicFieldName(field.Name) {
				fields = appendFieldSet(fields, &field)
			}
		}
		return fields
	case reflect.Map:
		return fields.Extend(FieldSetFromType(typ.Elem())...)
	case reflect.Slice:
		return fields.Extend(FieldSetFromType(typ.Elem())...)
	default:
		return fields
	}
}

func appendFieldSet(fields FieldSet, field *reflect.StructField) FieldSet {
	if id, ok := fieldsByName[field.Name]; ok {
		return fields.Add(id)
	}

	tag := string(field.Tag)
	fields = fields.Extend(FieldSetFromTag(tag)...)
	fields = fields.Extend(FieldSetFromType(field.Type)...)
	return fields
}

// FieldSetFromJSON checks top-level field names in a JSON object and produces the field set of all panther fields.
func FieldSetFromJSON(input []byte) (fields FieldSet) {
	obj := map[string]jsoniter.RawMessage{}
	if err := jsoniter.Unmarshal(input, &obj); err != nil {
		return nil
	}
	for key := range obj {
		if id, ok := fieldsByName[key]; ok {
			fields = fields.Add(id)
		}
	}
	return
}

// Len implements sort.Interface
func (fields FieldSet) Len() int {
	return len(fields)
}

// Less implements sort.Interface
func (fields FieldSet) Less(i, j int) bool {
	return fields[i] < fields[j]
}

// Swap implements sort.Interface
func (fields FieldSet) Swap(i, j int) {
	fields[i], fields[j] = fields[j], fields[i]
}
