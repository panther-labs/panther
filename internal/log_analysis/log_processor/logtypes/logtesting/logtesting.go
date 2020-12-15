package logtesting

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
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"text/template"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/omitempty"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

// RunTestsFromYAML reads all test cases in a YAML file and runs them.
func RunTestsFromYAML(t *testing.T, resolve logtypes.Finder, filename string) {
	t.Helper()
	f, err := os.Open(filename)
	if err != nil {
		t.Errorf("failed to open %q: %s", filename, err)
		return
	}
	dec := yaml.NewDecoder(f)
	dec.SetStrict(true)
	for {
		testCase := TestCase{
			Resolve: resolve,
		}
		if err := dec.Decode(&testCase); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("failed to read YAML test case: %s", err)
			return
		}
		t.Run(testCase.Name, testCase.Run)
	}
}

// RunTests is a helper that runs all test cases in sequence
func RunTests(t *testing.T, tests ...TestCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.Name, tc.Run)
	}
}

// TestCase is a test case validating the input and output for a parser
// TODO: add fields to allow test cases to test that a parser produces errors
type TestCase struct {
	Name    string          `json:"name" yaml:"name"`
	Input   string          `json:"input" yaml:"input"`
	Result  string          `json:"result" yaml:"result"`
	Results []string        `json:"results" yaml:"results"`
	LogType string          `json:"logType" yaml:"logType"`
	Resolve logtypes.Finder `json:"-" yaml:"-"`
}

// Run runs a test case
func (c *TestCase) Run(t *testing.T) {
	results := c.Results
	if c.Result != "" {
		results = append([]string{c.Result}, c.Results...)
	}
	TestRegisteredParser(t, c.Resolve, c.LogType, c.Input, results...)
}

// TestRegisteredParser is a helper to run a test for a registered log parser
func TestRegisteredParser(t *testing.T, resolve logtypes.Finder, logType, input string, expect ...string) {
	t.Helper()
	assert := require.New(t)
	if resolve == nil {
		resolve = logtypes.Must("empty")
	}
	entry := resolve.Find(logType)
	assert.NotNil(entry, "unresolved log type parser %q", logType)
	p, err := entry.NewParser(nil)
	assert.NoError(err, "failed to create log parser")
	results, err := p.ParseLog(input)
	assert.NoError(err)
	if len(expect) == 0 {
		require.Nil(t, results)
		return
	}
	schema := entry.Schema()
	indicators := pantherlog.FieldSetFromType(reflect.TypeOf(schema))
	assert.NotNil(results)
	assert.Equal(len(expect), len(results), "invalid number of pantherlog results produced by parser")
	for i, result := range results {
		expect := expect[i]
		expect = mustRenderExpect(expect, logType)
		TestResult(t, expect, result, indicators...)
	}
}

// JSON returns a jsoniter.API to be used for parser tests.
// The returned API forces omitempty to all fields and relies on global tcodec registration.
// It does not include conversion of output timestamp formats to make it easier to write test cases.
func JSON() jsoniter.API {
	api := jsoniter.Config{
		EscapeHTML:             true,
		SortMapKeys:            true,
		ValidateJsonRawMessage: true,
	}.Froze()
	api.RegisterExtension(omitempty.New("json"))
	return api
}

// Checks that `actual` is a parser result matching `expect`
// If expect.RowID is empty it checks if actual has non-empty RowID
// If expect.EventTime is zero it checks if actual.EventTime equals actual.ParseTime
// If expect.ParseTime is zero it checks if actual.ParseTime is non-zero
// Otherwise equality is checked strictly
func TestResult(t *testing.T, expect string, actual *pantherlog.Result, indicators ...pantherlog.FieldID) {
	t.Helper()
	logType := jsoniter.Get([]byte(expect), pantherlog.FieldLogTypeJSON).ToString()

	require.Equal(t, logType, actual.PantherLogType)
	expectResult := pantherlog.Result{}
	if indicators == nil {
		indicators = pantherlog.FieldSetFromJSON([]byte(expect))
	}
	require.NoError(t, unmarshalResultJSON([]byte(expect), &expectResult, indicators))
	var expectAny map[string]interface{}
	require.NoError(t, jsoniter.UnmarshalFromString(expect, &expectAny))
	var actualAny map[string]interface{}
	data, err := JSON().Marshal(actual)
	require.NoError(t, err)
	require.NoError(t, jsoniter.Unmarshal(data, &actualAny))
	require.False(t, actual.PantherParseTime.IsZero(), "zero parse time")
	if expectResult.PantherEventTime.IsZero() {
		EqualTimestamp(t, actual.PantherParseTime, actual.PantherEventTime, "event time not equal to parse time")
	} else {
		EqualTimestamp(t, expectResult.PantherEventTime, actual.PantherEventTime, "invalid event time")
	}
	require.NotEmpty(t, actual.PantherRowID)
	// The following dance ensures that produced JSON matches values from `actual` result
	require.Equal(t, actual.PantherEventTime.UTC().Format(time.RFC3339Nano), actualAny["p_event_time"], "Invalid JSON event time")
	require.Equal(t, actual.PantherParseTime.UTC().Format(time.RFC3339Nano), actualAny["p_parse_time"], "Invalid JSON parse time")
	require.Equal(t, actual.PantherRowID, actualAny["p_row_id"], "Invalid JSON row id")
	// Since these values are checked to be valid we assign them to expect to check the rest of the JSON values
	expectAny["p_event_time"] = actualAny["p_event_time"]
	expectAny["p_parse_time"] = actualAny["p_parse_time"]
	expectAny["p_row_id"] = actualAny["p_row_id"]
	// By now expect JSON and actual JSON must be equal
	expectJSON, err := jsoniter.MarshalToString(expectAny)
	require.NoError(t, err)
	actualJSON, err := jsoniter.MarshalToString(actualAny)
	require.NoError(t, err)
	require.JSONEq(t, expectJSON, actualJSON)
}

// EqualTimestamp is a helper that checks timestamps for equality with human readable message
func EqualTimestamp(t *testing.T, expect, actual time.Time, msgAndArgs ...interface{}) {
	t.Helper()
	require.NotZero(t, actual, msgAndArgs...)
	require.Equal(t, expect.UTC().Format(time.RFC3339Nano), actual.UTC().Format(time.RFC3339Nano), msgAndArgs...)
}

// unmarshalResultJSON unmarshals a result from JSON
// The parsing is inefficient. It's purpose is to be used in tests to verify output results.
func unmarshalResultJSON(data []byte, r *pantherlog.Result, indicators pantherlog.FieldSet) error {
	tmp := struct {
		LogType     string      `json:"p_log_type"`
		EventTime   tcodec.Time `json:"p_event_time" tcodec:"rfc3339"`
		ParseTime   tcodec.Time `json:"p_parse_time" tcodec:"rfc3339"`
		RowID       string      `json:"p_row_id"`
		SourceID    string      `json:"p_source_id"`
		SourceLabel string      `json:"p_source_label"`
	}{}
	if err := jsoniter.Unmarshal(data, &tmp); err != nil {
		return err
	}
	values := pantherlog.BlankValueBuffer()
	for _, kind := range indicators {
		fieldName := pantherlog.FieldNameJSON(kind)
		any := jsoniter.Get(data, fieldName)
		if any == nil || any.ValueType() == jsoniter.InvalidValue {
			continue
		}
		var v []string
		any.ToVal(&v)
		if v != nil {
			values.WriteValues(kind, v...)
		}
	}
	*r = pantherlog.Result{
		CoreFields: pantherlog.CoreFields{
			PantherLogType:     tmp.LogType,
			PantherRowID:       tmp.RowID,
			PantherEventTime:   tmp.EventTime,
			PantherParseTime:   tmp.ParseTime,
			PantherSourceID:    tmp.SourceID,
			PantherSourceLabel: tmp.SourceLabel,
		},
	}
	values.WriteValuesTo(r)
	values.Recycle()
	return nil
}

func mustRenderExpect(expect, logType string) string {
	tpl := template.Must(template.New(logType).Parse(expect))
	s := strings.Builder{}
	data := &struct {
		LogType string
	}{
		LogType: logType,
	}
	if err := tpl.Execute(&s, &data); err != nil {
		panic(err)
	}

	return s.String()
}
