package testutil

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

// used for test code that should NOT be in production code

import (
	"bufio"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/omitempty"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// For new parser tests use `CheckPantherParser` instead
// Used by log parsers to validate records
func EqualPantherLog(t *testing.T, expectedEvent *parsers.PantherLog, events []*parsers.PantherLog, parseErr error) {
	require.NoError(t, parseErr)
	require.Equal(t, 1, len(events))
	event := events[0]
	require.NotNil(t, event)
	require.NotNil(t, event.Event())

	// rowid changes each time
	require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
	expectedEvent.PantherRowID = event.PantherRowID

	// PantherParseTime is set to time.Now().UTC(). Require not nil
	require.NotNil(t, event.PantherParseTime)
	expectedEvent.PantherParseTime = event.PantherParseTime

	// For nil event times, expect Panther to set the event time to the parse time.
	if expectedEvent.PantherEventTime == nil {
		expectedEvent.PantherEventTime = event.PantherParseTime
	}

	// serialize as JSON using back pointers to compare
	expectedJSON, err := jsoniter.MarshalToString(expectedEvent.Event())
	require.NoError(t, err)
	eventJSON, err := jsoniter.MarshalToString(event.Event())
	require.NoError(t, err)

	require.JSONEq(t, expectedJSON, eventJSON)
}

func CheckPantherParser(t *testing.T, log string, parser parsers.LogParser, expect *parsers.PantherLog, expectMore ...*parsers.PantherLog) {
	t.Helper()
	p := parser.New()
	results, err := p.Parse(log)
	require.NoError(t, err)
	require.NotNil(t, results)
	// Prepend the required log arg to more
	expectMore = append([]*parsers.PantherLog{expect}, expectMore...)
	require.Equal(t, len(expectMore), len(results), "Invalid number of pather logs produced by parser")
	for i, result := range results {
		expect := expectMore[i]
		EqualPantherLog(t, expect, []*parsers.PantherLog{result}, nil)
	}
}

func MustReadFileString(filename string) string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func CheckParserSamplesJSONL(t *testing.T, filename string, parser parsers.LogParser) {
	t.Helper()
	blank := parser.New()
	lines := MustReadFileJSONLines(filename)
	for i, line := range lines {
		_, err := blank.Parse(line)
		require.NoError(t, err, "failed to parse line %d", i)
	}
}

func MustReadFileJSONLines(filename string) (lines []string) {
	fd, err := os.Open(filename)
	if err != nil {
		panic(errors.Wrapf(err, "Failed to open file %q", filename))
	}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 {
			lines = append(lines, scanner.Text())
		}
	}
	if scanner.Err() != nil {
		panic(errors.Wrap(scanner.Err(), "encountered issue while reading file"))
	}
	return
}

type ParserConfig map[string]interface{}

func AlwaysFailParser(err error) *MockParser {
	p := MockParser{}
	p.On("Parse", mock.AnythingOfType("string")).Return(([]*parsers.Result)(nil), err)
	return &p
}

type MockParser struct {
	mock.Mock
}

func (args ParserConfig) Parser() *MockParser {
	p := &MockParser{}
	for log, result := range args {
		var err error
		var results []*parsers.Result
		switch x := result.(type) {
		case error:
			err = x
		case []*parsers.PantherLog:
			results, err = parsers.ToResults(x, nil)
		case *parsers.PantherLog:
			results, err = x.Results()
		case []*parsers.Result:
			results = x
		case parsers.Result:
			results = []*parsers.Result{&x}
		case *parsers.Result:
			results = []*parsers.Result{x}
		}
		p.On("Parse", log).Return(results, err)
	}
	p.On("Parse", mock.AnythingOfType("string")).Return(([]*parsers.Result)(nil), errors.New("invalid log"))
	return p
}

func (p *MockParser) ParseLog(log string) ([]*parsers.Result, error) {
	args := p.MethodCalled("Parse", log)
	return args.Get(0).([]*parsers.Result), args.Error(1)
}

func (p *MockParser) RequireLessOrEqualNumberOfCalls(t *testing.T, method string, number int) {
	t.Helper()
	timesCalled := 0
	for _, call := range p.Calls {
		if call.Method == method {
			timesCalled++
		}
	}
	require.LessOrEqual(t, timesCalled, number)
}

func CheckPantherMultiline(t *testing.T, logs string, parser parsers.LogParser, expect ...*parsers.PantherLog) {
	t.Helper()
	p := parser.New()
	scanner := bufio.NewScanner(strings.NewReader(logs))
	var actual []*parsers.PantherLog
	for scanner.Scan() {
		log := scanner.Text()

		results, err := p.Parse(log)
		require.NoError(t, err)
		actual = append(actual, results...)
	}
	require.Equal(t, len(expect), len(actual))
	for i, result := range actual {
		expect := expect[i]
		EqualPantherLog(t, expect, []*parsers.PantherLog{result}, nil)
	}
}

func NewRawMessage(jsonString string) *jsoniter.RawMessage {
	rawMsg := (jsoniter.RawMessage)(jsonString)
	return &rawMsg
}

// CheckRegisteredParser checks a registered log type parser
func CheckRegisteredParser(t *testing.T, logType, input string, expect ...string) {
	t.Helper()
	entry := logtypes.DefaultRegistry().Get(logType)
	if !assert.NotNil(t, entry, "logtype %q not registered", logType) {
		return
	}
	p, err := entry.NewParser(nil)
	require.NoError(t, err, "failed to create log parser")
	results, err := p.ParseLog(input)
	require.NoError(t, err)
	if len(expect) == 0 {
		require.Nil(t, results)
		return
	}
	schema := entry.Schema()
	indicators := pantherlog.FieldSetFromType(reflect.TypeOf(schema))
	require.NotNil(t, results)
	require.Equal(t, len(expect), len(results), "Invalid number of patherlog results produced by parser")
	for i, result := range results {
		expect := expect[i]
		CheckParserResults(t, expect, result, indicators...)
	}
}

// CheckLogParser checks a log type parser
func CheckLogParser(t *testing.T, p parsers.Interface, input string, expect ...string) {
	t.Helper()
	results, err := p.ParseLog(input)
	require.NoError(t, err)
	if len(expect) == 0 {
		require.Nil(t, results)
		return
	}
	require.NotNil(t, results)
	require.Equal(t, len(expect), len(results), "Invalid number of patherlog results produced by parser")
	for i, result := range results {
		expect := expect[i]
		CheckParserResults(t, expect, result)
	}
}

func jsonAPI() jsoniter.API {
	api := jsoniter.Config{
		EscapeHTML:             true,
		SortMapKeys:            true,
		ValidateJsonRawMessage: true,
	}.Froze()
	api.RegisterExtension(omitempty.New("json"))
	//api.RegisterExtension(&tcodec.Extension{})
	return api
}

// Checks that `actual` is a parser result matching `expect`
// If expect.RowID is empty it checks if actual has non-empty RowID
// If expect.EventTime is zero it checks if actual.EventTime equals actual.ParseTime
// If expect.ParseTime is zero it checks if actual.ParseTime is non-zero
// Otherwise equality is checked strictly
func CheckParserResults(t *testing.T, want string, actual *pantherlog.Result, indicators ...pantherlog.FieldID) {
	t.Helper()
	logType := jsoniter.Get([]byte(want), pantherlog.FieldLogTypeJSON).ToString()
	require.Equal(t, logType, actual.PantherLogType, pantherlog.FieldLogTypeJSON)
	expect := pantherlog.Result{}
	if indicators == nil {
		indicators = pantherlog.FieldSetFromJSON([]byte(want))
	}
	require.NoError(t, UnmarshalResultJSON([]byte(want), &expect, indicators))
	//require.Equal(t, -1, bytes.IndexByte(actual.JSON, '\n'), "Result JSON contains newlines")
	var expectAny map[string]interface{}
	require.NoError(t, jsoniter.UnmarshalFromString(want, &expectAny))
	var actualAny map[string]interface{}
	data, err := jsonAPI().Marshal(actual)
	require.NoError(t, err)
	require.NoError(t, jsoniter.Unmarshal(data, &actualAny))
	if expect.PantherParseTime.IsZero() {
		require.False(t, actual.PantherParseTime.IsZero(), "zero parse time")
	} else {
		EqualTimestamp(t, expect.PantherParseTime, actual.PantherParseTime, "invalid parse time")
	}
	if expect.PantherEventTime.IsZero() {
		EqualTimestamp(t, actual.PantherParseTime, actual.PantherEventTime, "event time not equal to parse time")
	} else {
		EqualTimestamp(t, expect.PantherEventTime, actual.PantherEventTime, "invalid event time")
	}
	if len(expect.PantherRowID) == 0 {
		require.NotEmpty(t, actual.PantherRowID)
	} else {
		require.Equal(t, expect.PantherRowID, actual.PantherRowID)
	}
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

func EqualTimestamp(t *testing.T, expect, actual time.Time, msgAndArgs ...interface{}) {
	t.Helper()
	require.False(t, actual.IsZero(), "zero timestamp")
	require.Equal(t, expect.UTC().Format(time.RFC3339Nano), actual.UTC().Format(time.RFC3339Nano), msgAndArgs...)
}

// UnmarshalResultJSON unmarshals a result from JSON
// The parsing is inefficient. It's purpose is to be used in tests to verify output results.
func UnmarshalResultJSON(data []byte, r *pantherlog.Result, indicators pantherlog.FieldSet) error {
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
