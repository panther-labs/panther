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
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
	"github.com/panther-labs/panther/pkg/unbox"
)

type testEvent struct {
	Name      string                 `json:"@name"`
	Timestamp time.Time              `json:"ts" tcodec:"unix_ms" panther:"event_time"`
	IP        string                 `json:"ip" panther:"ip"`
	Domain    null.String            `json:"domain" panther:"domain"`
	Host      null.String            `json:"hostname" panther:"hostname"`
	TraceID   null.String            `json:"trace_id" panther:"trace_id"`
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

func (e *testEvent) WriteValuesTo(w pantherlog.ValueWriter) {
	e.Values.WriteValuesTo(w)
}

func newBuilder(id string, now time.Time) *pantherlog.ResultBuilder {
	return &pantherlog.ResultBuilder{
		LogType:   "TestEvent",
		NextRowID: pantherlog.StaticRowID(id),
		Now:       pantherlog.StaticNow(now),
	}
}

func TestNewResultBuilder(t *testing.T) {
	rowID := "id"
	now := time.Now().UTC()
	tm := now.Add(-time.Hour)
	b := newBuilder(rowID, now)
	event := testEvent{
		Name:      "event",
		IP:        "1.1.1.1",
		Host:      null.FromString("2.1.1.1"),
		TraceID:   null.FromString("foo"),
		Timestamp: tm,
	}

	result, err := b.BuildResult(&event)
	require.NoError(t, err)
	require.Equal(t, "TestEvent", result.LogType)
	testutil.EqualTimestamp(t, now, result.ParseTime)
	// Ensure event time is zero time
	require.Equal(t, time.Time{}, result.EventTime)
	require.Equal(t, rowID, result.RowID)
	expect := fmt.Sprintf(`{
		"p_row_id": "id",
		"p_log_type": "TestEvent",
		"p_event_time": "%s",
		"ts": "%s",
		"p_parse_time": "%s",
		"at_sign_name": "event",
		"ip": "1.1.1.1",
		"hostname": "2.1.1.1",
		"trace_id": "foo",
		"p_any_trace_ids": ["foo"],
		"p_any_ip_addresses": ["1.1.1.1","2.1.1.1"]
	}`,
		tm.Format(awsglue.TimestampLayout),
		tm.Format(awsglue.TimestampLayout),
		now.Format(awsglue.TimestampLayout),
	)
	buffer := bytes.Buffer{}
	require.NoError(t, result.WriteJSONTo(&buffer))
	actual := buffer.String()
	require.JSONEq(t, expect, actual)
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
		IP:        "1.1.1.1",
		Host:      null.FromString("2.1.1.1"),
		Timestamp: tm,
	}
	b.Run("old pantherlog", func(b *testing.B) {
		buffer := bytes.NewBuffer(make([]byte, 0, 8192))
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
			buffer.Reset()
			if err := result.WriteJSONTo(buffer); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("result builder", func(b *testing.B) {
		buffer := bytes.NewBuffer(make([]byte, 0, 8192))
		b.ReportAllocs()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			result, err := builder.BuildResult(event)
			if err != nil {
				b.Fatal(err)
			}
			buffer.Reset()
			if err := result.WriteJSONTo(buffer); err != nil {
				b.Fatal(err)
			}
		}
	})
}
