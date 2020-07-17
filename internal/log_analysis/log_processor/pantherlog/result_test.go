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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
	"github.com/panther-labs/panther/pkg/unbox"
)

type testEvent struct {
	Name      string                 `json:"@name"`
	Timestamp timestamp.RFC3339      `json:"ts"`
	IP        pantherlog.IPAddress   `json:"ip"`
	Domain    pantherlog.Domain      `json:"domain"`
	Host      pantherlog.Hostname    `json:"hostname"`
	TraceID   pantherlog.TraceID     `json:"trace_id"`
	Values    pantherlog.ValueBuffer `json:"-"`
}

type oldEvent struct {
	Name      *string            `json:"@name,omitempty"`
	IP        *string            `json:"ip,omitempty"`
	Domain    *string            `json:"domain,omitempty"`
	Host      *string            `json:"hostname,omitempty"`
	Timestamp *timestamp.RFC3339 `json:"ts,omitempty"`

	parsers.PantherLog
}

var _ pantherlog.Event = (*testEvent)(nil)

func (e *testEvent) WriteValuesTo(w pantherlog.ValueWriter) {
	e.Values.WriteValuesTo(w)
}
func (e *testEvent) PantherLogEvent() (string, *time.Time) {
	return e.Name, box.Time(time.Time(e.Timestamp))
}

func newBuilder(id string, now time.Time) *pantherlog.ResultBuilder {
	return &pantherlog.ResultBuilder{
		NextRowID: pantherlog.StaticRowID(id),
		Now:       pantherlog.StaticNow(now),
	}
}

func TestNewResultBuilder(t *testing.T) {
	rowID := "id"
	now := time.Now()
	tm := now.Add(-time.Hour)
	nowJSON := timestamp.AppendJSON(nil, now)
	tmJSON := timestamp.AppendJSON(nil, tm)

	b := newBuilder(rowID, now)
	event := testEvent{
		Name:      "event",
		IP:        pantherlog.ToIPAddress("1.1.1.1"),
		Host:      pantherlog.ToHostname("2.1.1.1"),
		TraceID:   pantherlog.ToTraceID("foo"),
		Timestamp: timestamp.RFC3339(tm),
	}

	result, err := b.BuildResult(&event)
	require.NoError(t, err)
	require.Equal(t, "event", result.LogType)
	require.Equal(t, now, result.ParseTime)
	require.Equal(t, tm, result.EventTime)
	require.Equal(t, rowID, result.RowID)
	expect := fmt.Sprintf(`{
		"p_row_id": "id",
		"p_log_type": "event",
		"p_event_time": %s,
		"ts": %s,
		"p_parse_time": %s,
		"at_sign_name": "event",
		"ip": "1.1.1.1",
		"hostname": "2.1.1.1",
		"trace_id": "foo",
		"p_any_trace_ids": ["foo"],
		"p_any_ip_addresses": ["1.1.1.1","2.1.1.1"]
}`, tmJSON, tmJSON, nowJSON)
	require.JSONEq(t, expect, string(result.JSON))
}

func BenchmarkResultBuilder(b *testing.B) {
	rowID := "id"
	now := time.Now()
	builder := newBuilder(rowID, now)
	tm := now.Add(-time.Hour)
	ts := (*timestamp.RFC3339)(&tm)
	old := oldEvent{
		Name:      box.String("event"),
		IP:        box.String("1.1.1.1"),
		Host:      box.String("2.1.1.1"),
		Timestamp: ts,
	}
	old.SetCoreFields("event", ts, &old)

	event := &testEvent{
		Name:      "event",
		IP:        pantherlog.ToIPAddress("1.1.1.1"),
		Host:      pantherlog.ToHostname("2.1.1.1"),
		Timestamp: timestamp.RFC3339(tm),
	}
	b.Run("old pantherlog", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			old.AppendAnyIPAddress("1.1.1.1")
			if !old.AppendAnyIPAddressPtr(old.Host) {
				old.AppendAnyDomainNames(unbox.String(old.Host))
			}
			result, err := old.Result()
			if err != nil {
				b.Fatal(err)
			}
			result.Close()
		}
	})
	b.Run("result builder", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := builder.BuildResult(event)
			if err != nil {
				b.Fatal(err)
			}
			result.Close()
		}
	})
}
