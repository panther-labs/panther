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
	"fmt"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue/gluetimestamp"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/omitempty"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
	"github.com/panther-labs/panther/pkg/unbox"
)

type testEvent struct {
	Name      string                  `json:"@name"`
	Timestamp time.Time               `json:"ts" tcodec:"unix_ms" event_time:"true"`
	IP        string                  `json:"ip" panther:"ip"`
	Domain    null.String             `json:"domain" panther:"domain"`
	Host      null.String             `json:"hostname" panther:"hostname"`
	TraceID   null.String             `json:"trace_id" panther:"trace_id"`
	Values    *pantherlog.ValueBuffer `json:"-"`
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
	if e.Values != nil {
		e.Values.WriteValuesTo(w)
	}
}

func newBuilder(id string, now time.Time) *pantherlog.ResultBuilder {
	return &pantherlog.ResultBuilder{
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

	api := buildAPI()
	result, err := b.BuildResult("TestEvent", &event)
	require.NoError(t, err)
	require.Equal(t, "TestEvent", result.PantherLogType)
	logtesting.EqualTimestamp(t, now, result.PantherParseTime)
	// Ensure event time is zero time
	require.Equal(t, time.Time{}, result.PantherEventTime)
	require.Equal(t, rowID, result.PantherRowID)
	expect := fmt.Sprintf(`{
		"p_row_id": "id",
		"p_log_type": "TestEvent",
		"p_event_time": "%s",
		"ts": %d,
		"p_parse_time": "%s",
		"@name": "event",
		"ip": "1.1.1.1",
		"hostname": "2.1.1.1",
		"trace_id": "foo",
		"p_any_trace_ids": ["foo"],
		"p_any_ip_addresses": ["1.1.1.1","2.1.1.1"]
	}`,
		tm.Format(time.RFC3339Nano),
		time.Duration(tm.UnixNano()).Milliseconds(),
		now.Format(time.RFC3339Nano),
	)
	actual, err := api.Marshal(result)
	require.NoError(t, err)
	require.JSONEq(t, expect, string(actual))
}
func TestOldResults(t *testing.T) {
	rowID := "id"
	now := time.Now().UTC()
	tm := now.Add(-time.Hour)
	event := oldEvent{
		Name:      box.String("event"),
		IP:        box.String("1.1.1.1"),
		Host:      box.String("2.1.1.1"),
		Timestamp: (*timestamp.RFC3339)(&tm),
		PantherLog: parsers.PantherLog{
			PantherLogType:   box.String("Foo"),
			PantherRowID:     box.String("id"),
			PantherEventTime: (*timestamp.RFC3339)(&tm),
			PantherParseTime: (*timestamp.RFC3339)(&now),
		},
	}
	event.SetEvent(&event)
	parsers.AppendAnyString(&event.PantherAnyIPAddresses, "1.1.1.1", "2.1.1.1")

	api := buildAPI()
	result := event.Result()
	require.Equal(t, "Foo", result.PantherLogType)
	logtesting.EqualTimestamp(t, now, result.PantherParseTime)
	// Ensure event time is zero time
	//require.Equal(t, time.Time{}, result.PantherEventTime)
	require.Equal(t, rowID, result.PantherRowID)
	expect := fmt.Sprintf(`{
		"p_row_id": "id",
		"p_log_type": "Foo",
		"p_event_time": "%s",
		"ts": "%s",
		"p_parse_time": "%s",
		"@name": "event",
		"ip": "1.1.1.1",
		"hostname": "2.1.1.1",
		"p_any_ip_addresses": ["1.1.1.1","2.1.1.1"]
	}`,
		tm.UTC().Format(gluetimestamp.Layout),
		tm.UTC().Format(gluetimestamp.Layout),
		now.Format(gluetimestamp.Layout),
	)
	actual, err := api.Marshal(result)
	require.NoError(t, err)
	require.JSONEq(t, expect, string(actual))
}

func buildAPI() jsoniter.API {
	api := jsoniter.Config{}.Froze()
	api.RegisterExtension(&tcodec.Extension{})
	api.RegisterExtension(omitempty.New(`json`))
	return api
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

	event := testEvent{
		Name:      "event",
		IP:        "1.1.1.1",
		Host:      null.FromString("2.1.1.1"),
		Timestamp: tm,
	}
	b.Run("old pantherlog", func(b *testing.B) {
		stream := jsoniter.NewStream(jsoniter.ConfigDefault, nil, 8192)
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			result := old
			result.AppendAnyIPAddress("1.1.1.1")
			if !result.AppendAnyIPAddressPtr(result.Host) {
				result.AppendAnyDomainNames(unbox.String(result.Host))
			}
			stream.Reset(nil)
			stream.WriteVal(&result)
			if err := stream.Error; err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("result builder", func(b *testing.B) {
		api := buildAPI()
		stream := jsoniter.NewStream(api, nil, 8192)
		b.ReportAllocs()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			localEvent := event
			result, err := builder.BuildResult("TestEvent", localEvent)
			if err != nil {
				b.Fatal(err)
			}
			stream.Reset(nil)
			stream.WriteVal(result)
			if err := stream.Error; err != nil {
				b.Fatal(err)
			}
		}
	})
}

type testEventTimer struct {
	Timestamp time.Time `json:"ts"`
	Foo       string    `json:"foo"`
}

var _ pantherlog.EventTimer = (*testEventTimer)(nil)

func (e *testEventTimer) PantherEventTime() time.Time {
	return e.Timestamp
}

func TestResultBuilder_BuildResult(t *testing.T) {
	now := time.Now().UTC()
	tm := now.Add(-1 * time.Hour)
	b := pantherlog.ResultBuilder{
		Now:       pantherlog.StaticNow(now),
		NextRowID: pantherlog.StaticRowID("42"),
	}
	event := &testEventTimer{
		Foo:       "bar",
		Timestamp: tm,
	}
	result, err := b.BuildResult("Foo", event)
	assert := require.New(t)
	assert.NoError(err)
	expect := &pantherlog.Result{
		CoreFields: pantherlog.CoreFields{
			PantherLogType:   "Foo",
			PantherEventTime: tm,
			PantherParseTime: now,
			PantherRowID:     "42",
		},
		Event: event,
	}
	assert.Equal(expect, result)
}
func TestSourceFields(t *testing.T) {
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

	api := buildAPI()
	result, err := b.BuildResult("TestEvent", &event)
	require.NoError(t, err)
	require.Equal(t, "TestEvent", result.PantherLogType)
	logtesting.EqualTimestamp(t, now, result.PantherParseTime)
	// Ensure event time is zero time
	require.Equal(t, time.Time{}, result.PantherEventTime)
	require.Equal(t, rowID, result.PantherRowID)
	result.PantherSourceLabel = "test-label"
	result.PantherSourceID = "test_id"
	expect := fmt.Sprintf(`{
		"p_row_id": "id",
		"p_log_type": "TestEvent",
		"p_event_time": "%s",
		"p_source_id": "test_id",
		"p_source_label": "test-label",
		"ts": %d,
		"p_parse_time": "%s",
		"@name": "event",
		"ip": "1.1.1.1",
		"hostname": "2.1.1.1",
		"trace_id": "foo",
		"p_any_trace_ids": ["foo"],
		"p_any_ip_addresses": ["1.1.1.1","2.1.1.1"]
	}`,
		tm.Format(time.RFC3339Nano),
		time.Duration(tm.UnixNano()).Milliseconds(),
		now.Format(time.RFC3339Nano),
	)
	actual, err := api.Marshal(result)
	require.NoError(t, err)
	require.JSONEq(t, expect, string(actual))
}
