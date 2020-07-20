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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
)

func TestMetaEventStruct(t *testing.T) {
	meta := pantherlog.Meta{
		pantherlog.KindIPAddress: {
			FieldName:     "Addresses",
			FieldNameJSON: "addresses",
			Description:   "The addresses",
		},
	}
	eventStruct := meta.EventStruct(&testEventMeta{})

	columns, names := awsglue.InferJSONColumns(eventStruct, awsglue.GlueMappings...)
	require.Equal(t, []string{}, names)
	// nolint: composites,lll
	require.Equal(t, []awsglue.Column{
		{"foo", "string", "foo", false},
		{"ts", "timestamp", "ts", false},
		{"addr", "string", "address", false},
		{"p_log_type", "string", "Panther added field with type of log", true},
		{"p_row_id", "string", "Panther added field with unique id (within table)", true},
		{"p_event_time", "timestamp", "Panther added standardize event time (UTC)", true},
		{"p_parse_time", "timestamp", "Panther added standardize log parse time (UTC)", true},
		{"addresses", "array<string>", "The addresses", false},
	}, columns)
}

type testEventMeta struct {
	Name      string            `json:"foo" description:"foo"`
	Timestamp timestamp.RFC3339 `json:"ts" description:"ts"`
	Address   null.String       `json:"addr" description:"address" panther:"ip"`
}

func (e *testEventMeta) PantherLogEvent() (string, *time.Time) {
	return e.Name, box.Time(time.Time(e.Timestamp))
}
