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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// FieldPrefix is the prefix for field names injected by panther to log events.
const FieldPrefix = "p_"

// DefaultMetaFields returns the default panther 'any' field mappings.
// It creates a new copy so that outside packages cannot affect the defaults.
func DefaultMetaFields() Meta {
	return Meta{
		KindIPAddress: {
			FieldName:     "PantherAnyIPAddresses",
			FieldNameJSON: "p_any_ip_addresses",
			Description:   "Panther added field with collection of ip addresses associated with the row",
		},
		KindDomainName: {
			FieldName:     "PantherAnyDomainNames",
			FieldNameJSON: "p_any_domain_names",
			Description:   "Panther added field with collection of domain names associated with the row",
		},
		KindSHA1Hash: {
			FieldName:     "PantherAnySHA1Hashes",
			FieldNameJSON: "p_any_sha1_hashes",
			Description:   "Panther added field with collection of SHA1 hashes associated with the row",
		},
		KindSHA256Hash: {
			FieldName:     "PantherAnySHA256Hashes",
			FieldNameJSON: "p_any_sha256_hashes",
			Description:   "Panther added field with collection of MD5 hashes associated with the row",
		},
		KindMD5Hash: {
			FieldName:     "PantherAnyMD5Hashes",
			FieldNameJSON: "p_any_md5_hashes",
			Description:   "Panther added field with collection of SHA256 hashes of any algorithm associated with the row",
		},
		KindTraceID: {
			FieldName:     "PantherAnyTraceIDs",
			FieldNameJSON: "p_any_trace_ids",
			Description:   "Panther added field with collection of context trace identifiers",
		},
	}
}

var defaultMetaFields = DefaultMetaFields()

type MetaField struct {
	FieldName     string
	FieldNameJSON string
	Description   string
}

func (m *MetaField) StructTag() reflect.StructTag {
	tag := fmt.Sprintf(`json:"%s,omitempty" description:"%s"`, m.FieldNameJSON, m.Description)
	return reflect.StructTag(tag)
}

type Meta map[ValueKind]*MetaField

func (meta Meta) EventStruct(event Event) interface{} {
	typ := reflect.TypeOf(event)
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
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
	fields := []reflect.StructField{
		{
			Name:  "PantherLogType",
			Tag:   `json:"p_log_type,omitempty" validate:"required" description:"Panther added field with type of log"`,
			Type:  reflect.TypeOf(""),
			Index: []int{0},
		},
		{
			Name:  "PantherRowID",
			Tag:   `json:"p_row_id,omitempty" validate:"required" description:"Panther added field with unique id (within table)"`,
			Type:  reflect.TypeOf(""),
			Index: []int{1},
		},
		{
			Name:  "PantherEventTime",
			Type:  reflect.TypeOf(&timestamp.RFC3339{}),
			Tag:   `json:"p_event_time,omitempty" validate:"required" description:"Panther added standardize event time (UTC)"`,
			Index: []int{2},
		},
		{
			Name:  "PantherParseTime",
			Type:  reflect.TypeOf(&timestamp.RFC3339{}),
			Tag:   `json:"p_parse_time,omitempty" validate:"required" description:"Panther added standardize log parse time (UTC)"`,
			Index: []int{3},
		},
	}
	// Produce ordered fields in the struct so doc generation is deterministic
	keys := make([]ValueKind, 0, len(meta))
	for kind := range meta {
		keys = append(keys, kind)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, kind := range keys {
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
