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
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

type mockParser struct {
	parsers.Interface
	mock.Mock
}

// Parse implements parsers.Parser interface
func (m *mockParser) Parse(log string) ([]*parsers.Result, error) {
	args := m.Called(log)
	result := args.Get(0)
	err := args.Error(1)
	if result == nil {
		return nil, err
	}
	return result.([]*parsers.Result), err
}

func newMockParser(err error, logs ...*parsers.Result) *mockParser {
	p := &mockParser{}
	p.On("Parse").Return(logs, err)
	return p
}

func mockLogType(name string, parser *mockParser) parsers.LogType {
	return parsers.LogType{
		Name:        name,
		Description: fmt.Sprintf("Mock log type %q", name),
		NewParser: func() parsers.Interface {
			return parser
		},
		Schema: struct{}{},
	}
}

var testRegistry *parsers.Registry

func TestClassifyRespectsPriorityOfParsers(t *testing.T) {
	parserSuccess := newMockParser(nil, &parsers.Result{})
	parserFail1 := newMockParser(errors.New("fail1"))
	parserFail2 := newMockParser(errors.New("fail2"))
	logTypeSuccess := mockLogType("success", parserSuccess)
	logTypeFail1 := mockLogType("failure1", parserFail1)
	logTypeFail2 := mockLogType("failure2", parserFail2)

	// Reset registry
	r, err := parsers.NewRegistry(
		logTypeSuccess,
		logTypeFail1,
		logTypeFail2,
	)
	require.NoError(t, err)
	classifier := NewClassifier(r)

	logLine := "log"

	repetitions := 1000

	expectedResult := &ClassifierResult{
		Events:  []*parsers.Result{{}},
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

	parserSuccess.AssertNumberOfCalls(t, "Parse", repetitions)

	require.NotNil(t, classifier.ParserStats()["success"])
	// skipping validating the times
	expectedParserStats.ParserTimeMicroseconds = classifier.ParserStats()["success"].ParserTimeMicroseconds
	require.Equal(t, expectedParserStats, classifier.ParserStats()["success"])

	requireLessOrEqualNumberOfCalls(t, parserFail1, "Parse", 1)
	require.Nil(t, classifier.ParserStats()["failure1"])
	require.Nil(t, classifier.ParserStats()["failure2"])
}

func TestClassifyNoMatch(t *testing.T) {
	failingParser := &mockParser{}
	failingParser.On("Parse", mock.Anything).Return(nil)

	logType := mockLogType("failure", failingParser)
	r, err := parsers.NewRegistry(logType)
	require.NoError(t, err)
	classifier := NewClassifier(r)

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
	require.Nil(t, classifier.ParserStats()[logType.Name])
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
	panicLogType := mockLogType("panic", panicParser)
	r, err := parsers.NewRegistry(panicLogType)
	require.NoError(t, err)
	classifier := NewClassifier(r)

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
	failingParser1 := newMockParser(nil)
	failingParser2 := newMockParser(nil)
	logType1 := mockLogType("failure1", failingParser1)
	logType2 := mockLogType("failure2", failingParser2)

	r, err := parsers.NewRegistry(
		logType1,
		logType2,
	)
	require.NoError(t, err)
	classifier := NewClassifier(r)

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
	require.Nil(t, classifier.ParserStats()[logType1.Name])
	require.Nil(t, classifier.ParserStats()[logType2.Name])
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
