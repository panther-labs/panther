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

	"github.com/pkg/errors"
)

const (
	// FieldPrefix is the prefix for field names injected by panther to log events.
	FieldPrefix    = "p_"
	FieldLogType   = FieldPrefix + "log_type"
	FieldRowID     = FieldPrefix + "row_id"
	FieldEventTime = FieldPrefix + "event_time"
	FieldParseTime = FieldPrefix + "parse_time"
)

var (
	typStringSlice = reflect.TypeOf([]string(nil))
	registeredMeta = Meta{
		KindIPAddress: {
			FieldName:     "PantherAnyIPAddresses",
			FieldNameJSON: "p_any_ip_addresses",
			Description:   "Panther added field with collection of ip addresses associated with the row",
			typ:           typStringSlice,
			kind:          KindIPAddress,
		},
		KindDomainName: {
			FieldName:     "PantherAnyDomainNames",
			FieldNameJSON: "p_any_domain_names",
			Description:   "Panther added field with collection of domain names associated with the row",
			kind:          KindDomainName,
		},
		KindSHA1Hash: {
			FieldName:     "PantherAnySHA1Hashes",
			FieldNameJSON: "p_any_sha1_hashes",
			Description:   "Panther added field with collection of SHA1 hashes associated with the row",
			typ:           typStringSlice,
			kind:          KindSHA1Hash,
		},
		KindSHA256Hash: {
			FieldName:     "PantherAnySHA256Hashes",
			FieldNameJSON: "p_any_sha256_hashes",
			Description:   "Panther added field with collection of MD5 hashes associated with the row",
			typ:           typStringSlice,
			kind:          KindSHA256Hash,
		},
		KindMD5Hash: {
			FieldName:     "PantherAnyMD5Hashes",
			FieldNameJSON: "p_any_md5_hashes",
			Description:   "Panther added field with collection of SHA256 hashes of any algorithm associated with the row",
			typ:           typStringSlice,
			kind:          KindMD5Hash,
		},
		KindTraceID: {
			FieldName:     "PantherAnyTraceIDs",
			FieldNameJSON: "p_any_trace_ids",
			Description:   "Panther added field with collection of context trace identifiers",
			typ:           typStringSlice,
			kind:          KindTraceID,
		},
	}
	coreFields = []*MetaField{
		{
			FieldName:     "PantherEventTime",
			FieldNameJSON: FieldEventTime,
			Description:   "Panther added standardized event time (UTC)",
			typ:           typTime,
		},
		{
			FieldName:     "PantherParseTime",
			FieldNameJSON: FieldParseTime,
			Description:   "Panther added standardize log parse time (UTC)",
			typ:           typTime,
		},
		{
			FieldName:     "PantherLogType",
			FieldNameJSON: FieldLogType,
			Description:   "Panther added field with type of log",
			typ:           typString,
		},
		{
			FieldName:     "PantherRowID",
			FieldNameJSON: FieldRowID,
			Description:   "Panther added field with unique id (within table)",
			typ:           typString,
		},
	}
	metaByFieldName = func() map[string]ValueKind {
		index := make(map[string]ValueKind)
		for _, m := range coreFields {
			if _, duplicate := index[m.FieldName]; duplicate {
				panic(`duplicate core field`)
			}
			if _, duplicate := index[m.FieldNameJSON]; duplicate {
				panic(`duplicate core field JSON`)
			}
			index[m.FieldName] = KindNone
			index[m.FieldNameJSON] = KindNone
		}
		for kind, m := range registeredMeta {
			if _, duplicate := index[m.FieldName]; duplicate {
				panic(`duplicate meta field`)
			}
			if _, duplicate := index[m.FieldNameJSON]; duplicate {
				panic(`duplicate meta field JSON`)
			}
			index[m.FieldName] = kind
			index[m.FieldNameJSON] = kind
		}
		return index
	}()
)

func MustRegisterMeta(kind ValueKind, field MetaField) {
	if err := RegisterMeta(kind, field); err != nil {
		panic(err)
	}
}

func RegisterMeta(kind ValueKind, field MetaField) error {
	if kind == KindNone {
		return errors.New(`zero value kind`)
	}
	if !strings.HasPrefix(field.FieldName, "Panther") {
		return errors.Errorf(`invalid field name %q`, field.FieldName)
	}
	if !strings.HasPrefix(field.FieldNameJSON, FieldPrefix) {
		return errors.Errorf(`invalid field name JSON %q`, field.FieldNameJSON)
	}
	if _, duplicate := registeredMeta[kind]; duplicate {
		return errors.Errorf(`duplicate field kind %d`, kind)
	}
	if _, duplicateFieldName := metaByFieldName[field.FieldName]; duplicateFieldName {
		return errors.Errorf(`duplicate field name %q`, field.FieldName)
	}
	if _, duplicateFieldNameJSON := metaByFieldName[field.FieldName]; duplicateFieldNameJSON {
		return errors.Errorf(`duplicate JSON field name %q`, field.FieldName)
	}
	field.typ = typStringSlice
	field.kind = kind
	registeredMeta[kind] = &field
	metaByFieldName[field.FieldName] = kind
	metaByFieldName[field.FieldNameJSON] = kind
	return nil
}

func BuildMeta(kinds ...ValueKind) Meta {
	meta := Meta{}
	for _, kind := range kinds {
		if kind == KindNone {
			continue
		}
		if m, ok := registeredMeta[kind]; ok {
			meta[kind] = m
		}
	}
	return meta
}

// DefaultMetaFields returns the default panther 'any' field mappings.
// It creates a new copy so that outside packages cannot affect the defaults.
func DefaultMetaFields() Meta {
	return BuildMeta(
		KindIPAddress,
		KindDomainName,
		KindSHA256Hash,
		KindSHA1Hash,
		KindMD5Hash,
		KindTraceID,
	)
}

var defaultMetaFields = DefaultMetaFields()

type MetaField struct {
	FieldName     string
	FieldNameJSON string
	Description   string
	typ           reflect.Type
	kind          ValueKind
}

func (m *MetaField) StructField(index int) reflect.StructField {
	return reflect.StructField{
		Name:  m.FieldName,
		Tag:   m.StructTag(),
		Type:  m.typ,
		Index: []int{index},
	}
}
func (m *MetaField) StructTag() reflect.StructTag {
	var tag string
	if m.IsCore() {
		tag = fmt.Sprintf(`json:"%s" validate:"required" description:"%s"`, m.FieldNameJSON, m.Description)
	} else {
		tag = fmt.Sprintf(`json:"%s,omitempty" description:"%s"`, m.FieldNameJSON, m.Description)
	}
	return reflect.StructTag(tag)
}

type Meta map[ValueKind]*MetaField

func (m *MetaField) IsCore() bool {
	return m.kind == KindNone
}

func (meta Meta) EventStruct(event interface{}) interface{} {
	typ := reflect.TypeOf(event)
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		panic(`non struct event`)
	}
	eventType := meta.EventStructType(typ)
	tmp := reflect.New(eventType)
	return tmp.Interface()
}

func (meta Meta) EventStructType(eventType reflect.Type) reflect.Type {
	return reflect.StructOf([]reflect.StructField{
		{
			Anonymous: true,
			Name:      "Event",
			Type:      eventType,
			Index:     []int{0},
		},
		{
			Anonymous: true,
			Name:      "PantherLog",
			Type:      meta.StructType(),
			Index:     []int{1},
		},
	})
}

func (meta Meta) StructType() reflect.Type {
	fields := []reflect.StructField{}
	for i, m := range coreFields {
		fields = append(fields, m.StructField(i))
	}
	// Use ordered fields in the struct so doc generation is deterministic
	for _, kind := range meta.Kinds() {
		m := meta[kind]
		fields = append(fields, reflect.StructField{
			Name:  strings.ToTitle(m.FieldName),
			Type:  reflect.TypeOf([]string{}),
			Tag:   m.StructTag(),
			Index: []int{len(fields)},
		})
	}
	return reflect.StructOf(fields)
}

func (meta Meta) Kinds() (kinds []ValueKind) {
	for kind := range meta {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool {
		return kinds[i] < kinds[j]
	})
	return
}
