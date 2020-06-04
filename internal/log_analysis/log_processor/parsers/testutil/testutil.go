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
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// used by log parsers to validate records
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
	p.On("Parse", mock.AnythingOfType("string")).Return(([]*pantherlog.Result)(nil), err)
	return &p
}

type MockParser struct {
	mock.Mock
}

func (args ParserConfig) Parser() *MockParser {
	p := &MockParser{}
	for log, result := range args {
		var err error
		var results []*pantherlog.Result
		switch x := result.(type) {
		case error:
			err = x
		case []*parsers.PantherLog:
			results, err = parsers.ToResults(x, nil)
		case *parsers.PantherLog:
			results, err = x.Results()
		case []*pantherlog.Result:
			results = x
		case pantherlog.Result:
			results = x.Results()
		case *pantherlog.Result:
			results = x.Results()
		}
		p.On("Parse", log).Return(results, err)
	}
	p.On("Parse", mock.AnythingOfType("string")).Return(([]*pantherlog.Result)(nil), errors.New("invalid log"))
	return p
}

func (p *MockParser) ParseLog(log string) ([]*pantherlog.Result, error) {
	args := p.MethodCalled("Parse", log)
	return args.Get(0).([]*pantherlog.Result), args.Error(1)
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
