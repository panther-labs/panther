package classification

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

type mockParser struct {
	parsers.LogParser
	mock.Mock
}

func (m *mockParser) New() parsers.LogParser {
	return m // pass through (not stateful)
}

func (m *mockParser) Parse(log string) ([]*parsers.PantherLog, error) {
	args := m.Called(log)
	result := args.Get(0)
	err := args.Error(1)
	if result == nil {
		return nil, err
	}
	return result.([]*parsers.PantherLog), err
}

func (m *mockParser) LogType() string {
	args := m.Called()
	return args.String(0)
}

// admit to registry.Interface interface
type TestRegistry map[string]*registry.LogParserMetadata

func NewTestRegistry() TestRegistry {
	return make(map[string]*registry.LogParserMetadata)
}

func (r TestRegistry) Add(lpm *registry.LogParserMetadata) {
	r[lpm.Parser.LogType()] = lpm
}

func (r TestRegistry) Elements() map[string]*registry.LogParserMetadata {
	return r
}

func (r TestRegistry) LookupParser(logType string) (lpm *registry.LogParserMetadata) {
	return (registry.Registry)(r).LookupParser(logType) // call registry code
}

func TestClassifyRespectsPriorityOfParsers(t *testing.T) {
	succeedingParser := &mockParser{}
	failingParser1 := &mockParser{}
	failingParser2 := &mockParser{}

	succeedingParser.On("Parse", mock.Anything).Return([]*parsers.PantherLog{{}}, nil)
	succeedingParser.On("LogType").Return("success")
	failingParser1.On("Parse", mock.Anything).Return(nil, errors.New("fail1"))
	failingParser1.On("LogType").Return("failure1")
	failingParser2.On("Parse", mock.Anything).Return(nil, errors.New("fail2"))
	failingParser2.On("LogType").Return("failure2")

	availableParsers := []*registry.LogParserMetadata{
		{Parser: failingParser1},
		{Parser: succeedingParser},
		{Parser: failingParser2},
	}
	testRegistry := NewTestRegistry()
	parserRegistry = testRegistry // re-bind as interface
	for i := range availableParsers {
		testRegistry.Add(availableParsers[i]) // update registry
	}

	classifier := NewClassifier()

	logLine := "log"

	repetitions := 1000

	expectedResult := &ClassifierResult{
		Events:  []*parsers.PantherLog{{}},
		LogType: aws.String("success"),
	}
	expectedStats := &ClassifierStats{
		BytesProcessedCount:         uint64(repetitions * len(logLine)),
		LogLineCount:                uint64(repetitions),
		EventCount:                  uint64(repetitions),
		SuccessfullyClassifiedCount: uint64(repetitions),
		ClassificationFailureCount:  0,
	}
	expectedParserStats := &ParserStats{
		BytesProcessedCount: uint64(repetitions * len(logLine)),
		LogLineCount:        uint64(repetitions),
		EventCount:          uint64(repetitions),
		LogType:             "success",
	}

	for i := 0; i < repetitions; i++ {
		result := classifier.Classify(logLine)
		require.Equal(t, expectedResult, result)
	}

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	succeedingParser.AssertNumberOfCalls(t, "Parse", repetitions)
	require.NotNil(t, classifier.ParserStats()[succeedingParser.LogType()])
	// skipping validating the times
	expectedParserStats.ParserTimeMicroseconds = classifier.ParserStats()[succeedingParser.LogType()].ParserTimeMicroseconds
	require.Equal(t, expectedParserStats, classifier.ParserStats()[succeedingParser.LogType()])

	requireLessOrEqualNumberOfCalls(t, failingParser1, "Parse", 1)
	require.Nil(t, classifier.ParserStats()[failingParser1.LogType()])
	require.Nil(t, classifier.ParserStats()[failingParser2.LogType()])
}

func TestClassifyNoMatch(t *testing.T) {
	failingParser := &mockParser{}

	failingParser.On("Parse", mock.Anything).Return(nil)
	failingParser.On("LogType").Return("failure")

	availableParsers := []*registry.LogParserMetadata{
		{Parser: failingParser},
	}
	testRegistry := NewTestRegistry()
	parserRegistry = testRegistry // re-bind as interface
	for i := range availableParsers {
		testRegistry.Add(availableParsers[i]) // update registry
	}

	classifier := NewClassifier()

	logLine := "log"

	expectedStats := &ClassifierStats{
		BytesProcessedCount:         uint64(len(logLine)),
		LogLineCount:                1,
		EventCount:                  0,
		SuccessfullyClassifiedCount: 0,
		ClassificationFailureCount:  1,
	}

	result := classifier.Classify(logLine)

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	require.Equal(t, &ClassifierResult{}, result)
	failingParser.AssertNumberOfCalls(t, "Parse", 1)
	require.Nil(t, classifier.ParserStats()[failingParser.LogType()])
}

func TestClassifyParserPanic(t *testing.T) {
	// uncomment to see the logs produced
	/*
		logger := zap.NewExample()
		defer logger.Sync()
		undo := zap.ReplaceGlobals(logger)
		defer undo()
	*/

	panicParser := &mockParser{}

	panicParser.On("Parse", mock.Anything).Run(func(args mock.Arguments) { panic("test parser panic") })
	panicParser.On("LogType").Return("panic parser")

	availableParsers := []*registry.LogParserMetadata{
		{Parser: panicParser},
	}
	testRegistry := NewTestRegistry()
	parserRegistry = testRegistry // re-bind as interface
	for i := range availableParsers {
		testRegistry.Add(availableParsers[i]) // update registry
	}

	classifier := NewClassifier()

	logLine := "log of death"

	expectedStats := &ClassifierStats{
		BytesProcessedCount:         uint64(len(logLine)),
		LogLineCount:                1,
		EventCount:                  0,
		SuccessfullyClassifiedCount: 0,
		ClassificationFailureCount:  1,
	}

	result := classifier.Classify(logLine)

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	require.Equal(t, &ClassifierResult{}, result)
	panicParser.AssertNumberOfCalls(t, "Parse", 1)
}

func TestClassifyNoLogline(t *testing.T) {
	testSkipClassify("", t)
}

func TestClassifyLogLineIsWhiteSpace(t *testing.T) {
	testSkipClassify("\n", t)
	testSkipClassify("\n\r", t)
	testSkipClassify("   ", t)
	testSkipClassify("\t", t)
}

func testSkipClassify(logLine string, t *testing.T) {
	// this tests the shortcut path where if log line == "" or "<whitepace>" we just skip
	failingParser1 := &mockParser{}
	failingParser2 := &mockParser{}

	failingParser1.On("Parse", mock.Anything).Return(nil)
	failingParser1.On("LogType").Return("failure1")
	failingParser2.On("Parse", mock.Anything).Return(nil)
	failingParser2.On("LogType").Return("failure2")

	availableParsers := []*registry.LogParserMetadata{
		{Parser: failingParser1},
		{Parser: failingParser2},
	}
	testRegistry := NewTestRegistry()
	parserRegistry = testRegistry // re-bind as interface
	for i := range availableParsers {
		testRegistry.Add(availableParsers[i]) // update registry
	}

	classifier := NewClassifier()

	repetitions := 1000

	var expectedLogLineCount uint64 = 0
	if len(logLine) > 0 { // when there is NO log line we return without counts.
		expectedLogLineCount = uint64(repetitions) // if there is a log line , but white space, we count, then return
	}
	expectedResult := &ClassifierResult{}
	expectedStats := &ClassifierStats{
		BytesProcessedCount:         0,
		LogLineCount:                expectedLogLineCount,
		EventCount:                  0,
		SuccessfullyClassifiedCount: 0,
		ClassificationFailureCount:  0,
	}

	for i := 0; i < repetitions; i++ {
		result := classifier.Classify(logLine)
		require.Equal(t, expectedResult, result)
	}

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	requireLessOrEqualNumberOfCalls(t, failingParser1, "Parse", 1)
	require.Nil(t, classifier.ParserStats()[failingParser1.LogType()])
	require.Nil(t, classifier.ParserStats()[failingParser2.LogType()])
}

func requireLessOrEqualNumberOfCalls(t *testing.T, underTest *mockParser, method string, number int) {
	timesCalled := 0
	for _, call := range underTest.Calls {
		if call.Method == method {
			timesCalled++
		}
	}
	require.LessOrEqual(t, timesCalled, number)
}
