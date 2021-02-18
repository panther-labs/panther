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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/pkg/box"
)

type testStringer struct {
	Foo string
}

func (t *testStringer) String() string {
	return t.Foo
}
func (t *testStringer) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Foo)
}

var (
	// Register our own random value kinds
	kindFoo  = FieldID(time.Now().UnixNano())
	kindBar  = kindFoo + 1
	kindBaz  = kindFoo + 2
	kindQux  = kindFoo + 3
	kindQuux = kindFoo + 4
)

func init() {
	MustRegisterIndicator(kindFoo, FieldMeta{
		Name:        "PantherFoo",
		NameJSON:    "p_any_foo",
		Description: "Foo data",
	})
	MustRegisterIndicator(kindBar, FieldMeta{
		Name:        "PantherBar",
		NameJSON:    "p_any_bar",
		Description: "Bar data",
	})
	MustRegisterIndicator(kindBaz, FieldMeta{
		Name:        "PantherBaz",
		NameJSON:    "p_any_baz",
		Description: "Baz data",
	})
	MustRegisterIndicator(kindQux, FieldMeta{
		Name:        "PantherQux",
		NameJSON:    "p_any_qux",
		Description: "Qux data",
	})
	MustRegisterIndicator(kindQuux, FieldMeta{
		Name:        "PantherQuux",
		NameJSON:    "p_any_quux",
		Description: "Quux data",
	})
	MustRegisterScanner("foo", kindFoo, kindFoo)
	MustRegisterScanner("bar", kindBar, kindBar)
	MustRegisterScanner("baz", kindBaz, kindBaz)
	MustRegisterScanner("qux", kindQux, kindQux)
	MustRegisterScanner("quux", kindQuux, kindQuux)
}

func TestPantherExt_DecorateEncoder(t *testing.T) {
	// Check all possible string types
	type T struct {
		Foo      testStringer  `json:"foo" panther:"foo"`
		Bar      testStringer  `json:"bar" panther:"bar"`
		Baz      string        `json:"baz" panther:"baz"`
		Qux      *string       `json:"qux" panther:"qux"`
		Quux     null.String   `json:"quux" panther:"quux"`
		FooSlice []string      `json:"foos" panther:"foo"`
		BarSlice []null.String `json:"bars" panther:"bar"`
		QuxSlice []*string     `json:"quxs" panther:"qux"`
	}

	v := T{
		Foo: testStringer{
			Foo: "ok",
		},
		Bar: testStringer{
			Foo: "ok",
		},
		Baz:      "baz",
		Qux:      box.String("qux"),
		Quux:     null.FromString("quux"),
		FooSlice: []string{"in", "slice"},
		BarSlice: []null.String{null.FromString("in"), null.FromString("slice")},
		QuxSlice: []*string{box.String("qux1"), box.String("qux2"), nil},
	}

	result := Result{
		values: new(ValueBuffer),
	}
	stream := jsoniter.ConfigDefault.BorrowStream(nil)
	stream.Attachment = &result
	stream.WriteVal(&v)
	require.Equal(t, []string{"in", "ok", "slice"}, result.values.Get(kindFoo), "foo")
	require.Equal(t, []string{"in", "ok", "slice"}, result.values.Get(kindBar), "bar")
	require.Equal(t, []string{"baz"}, result.values.Get(kindBaz), "baz")
	require.Equal(t, []string{"qux", "qux1", "qux2"}, result.values.Get(kindQux), "qux")
	require.Equal(t, []string{"quux"}, result.values.Get(kindQuux), "quux")
	actual := string(stream.Buffer())
	//nolint:lll
	require.Equal(t, `{"foo":"ok","bar":"ok","baz":"baz","qux":"qux","quux":"quux","foos":["in","slice"],"bars":["in","slice"],"quxs":["qux1","qux2",null]}`, actual)
}

func TestResultEncoder(t *testing.T) {
	now := time.Now()
	tm := now.Add(-1 * time.Minute)
	loc, err := time.LoadLocation(`Europe/Athens`)
	assert := require.New(t)
	assert.NoError(err)
	type T struct {
		Time     time.Time `json:"tm" event_time:"true"`
		RemoteIP string    `json:"remote_ip" panther:"ip"`
		LocalIP  string    `json:"local_ip" panther:"ip"`
		Tags     []string  `json:"tags" panther:"aws_tag"`
	}
	event := T{
		Time:     tm.In(loc),
		RemoteIP: "2.2.2.2",
		LocalIP:  "1.1.1.1",
		Tags:     []string{"foo:bar", "bar:baz"},
	}
	result := Result{
		CoreFields: CoreFields{
			PantherLogType:   "Foo.Bar",
			PantherRowID:     "id",
			PantherParseTime: now.UTC(),
		},
		Event: &event,
	}
	actual, err := jsoniter.MarshalToString(&result)
	assert.NoError(err)
	expect := fmt.Sprintf(`{
		"tm": "%s",
		"remote_ip":"2.2.2.2",
		"local_ip":"1.1.1.1",
		"tags": ["foo:bar","bar:baz"],
		"p_row_id": "id",
		"p_event_time": "%s",
		"p_parse_time": "%s",
		"p_any_ip_addresses": ["1.1.1.1", "2.2.2.2"],
		"p_any_aws_tags": ["bar:baz","foo:bar"],
		"p_log_type": "Foo.Bar"
	}`, tm.In(loc).Format(time.RFC3339Nano), tm.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	assert.JSONEq(expect, actual)
}

func TestResultEncoderEmptyEvent(t *testing.T) {
	now := time.Now()
	assert := require.New(t)
	type T struct {
		Data string `json:"data,omitempty"`
	}
	event := T{}
	result := Result{
		CoreFields: CoreFields{
			PantherLogType:   "Foo.Bar",
			PantherRowID:     "id",
			PantherParseTime: now.UTC(),
		},
		Event: &event,
	}
	actual, err := jsoniter.MarshalToString(&result)
	assert.NoError(err)
	expect := fmt.Sprintf(`{
		"p_row_id": "id",
		"p_event_time": "%s",
		"p_parse_time": "%s",
		"p_log_type": "Foo.Bar"
	}`, now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	assert.JSONEq(expect, actual)
}

func TestResultEncoderNilEvent(t *testing.T) {
	now := time.Now()
	assert := require.New(t)
	result := Result{
		CoreFields: CoreFields{
			PantherLogType:   "Foo.Bar",
			PantherRowID:     "id",
			PantherParseTime: now.UTC(),
		},
		Event: nil,
	}
	actual, err := jsoniter.MarshalToString(&result)
	assert.NoError(err)
	expect := fmt.Sprintf(`{
		"p_row_id": "id",
		"p_event_time": "%s",
		"p_parse_time": "%s",
		"p_log_type": "Foo.Bar"
	}`, now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	assert.JSONEq(expect, actual)
}
