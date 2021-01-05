package pantherlog_test

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
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestMetaEventStruct(t *testing.T) {
	eventStruct := pantherlog.MustBuildEventSchema(&testEventMeta{}, pantherlog.FieldDomainName)

	columns, mappings, err := glueschema.InferColumnsWithMappings(eventStruct)
	require.NoError(t, err)
	// nolint:lll
	expectMappings := map[string]string{
		"addr":               "addr",
		"foo":                "foo",
		"p_any_domain_names": "p_any_domain_names",
		"p_any_ip_addresses": "p_any_ip_addresses",
		"p_event_time":       "p_event_time",
		"p_log_type":         "p_log_type",
		"p_parse_time":       "p_parse_time",
		"p_row_id":           "p_row_id",
		"p_source_id":        "p_source_id",
		"p_source_label":     "p_source_label",
		"ts":                 "ts",
	}
	require.Equal(t, expectMappings, mappings)
	// nolint: lll,govet
	require.Equal(t, []awsglue.Column{
		{"foo", "string", "foo", false},
		{"ts", "timestamp", "ts", false},
		{"addr", "string", "address", false},
		{"p_event_time", "timestamp", "Panther added standardized event time (UTC)", true},
		{"p_parse_time", "timestamp", "Panther added standardized log parse time (UTC)", true},
		{"p_log_type", "string", "Panther added field with type of log", true},
		{"p_row_id", "string", "Panther added field with unique id (within table)", true},
		{"p_source_id", "string", "Panther added field with the source id", false},
		{"p_source_label", "string", "Panther added field with the source label", false},
		{"p_any_ip_addresses", "array<string>", "Panther added field with collection of ip addresses associated with the row", false},
		{"p_any_domain_names", "array<string>", "Panther added field with collection of domain names associated with the row", false},
	}, columns)
}

func TestMultipleIndicatorScanners(t *testing.T) {
	type T struct {
		Foo pantherlog.String `json:"foo" panther:"username,trace_id"`
	}
	eventStruct := pantherlog.MustBuildEventSchema(T{}, pantherlog.FieldDomainName)

	assert := require.New(t)
	_, ok := reflect.TypeOf(eventStruct).Elem().FieldByName("PantherAnyUsernames")
	assert.True(ok, "has usernames")
	_, ok = reflect.TypeOf(eventStruct).Elem().FieldByName("PantherAnyDomainNames")
	assert.True(ok, "has domain names")
	_, ok = reflect.TypeOf(eventStruct).Elem().FieldByName("PantherAnyTraceIDs")
	assert.True(ok, "has trace ids")
}

type testEventMeta struct {
	Name      string            `json:"foo" description:"foo"`
	Timestamp timestamp.RFC3339 `json:"ts" description:"ts"`
	Address   null.String       `json:"addr" description:"address" panther:"ip,arn"`
}

func TestRequiredFields(t *testing.T) {
	assert := require.New(t)
	fields := pantherlog.FieldSetFromType(reflect.TypeOf(testEventMeta{}))
	assert.Equal(pantherlog.NewFieldSet(pantherlog.FieldIPAddress), fields)
}

func TestFieldSetFromTag(t *testing.T) {
	assert := require.New(t)
	expect := pantherlog.NewFieldSet(pantherlog.FieldIPAddress, pantherlog.FieldDomainName)
	sort.Sort(expect)
	actual := pantherlog.FieldSetFromTag(`json:"foo" panther:"hostname"`)
	sort.Sort(actual)
	assert.Equal(expect, actual)
}
