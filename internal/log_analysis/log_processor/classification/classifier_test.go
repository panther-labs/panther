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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
)

func mockLogType(name string, parser parsers.Interface) parsers.LogType {
	return parsers.LogType{
		Name:        name,
		Description: fmt.Sprintf("Mock log type %q", name),
		NewParser: func() parsers.Interface {
			return parser
		},
		Schema: struct{}{},
	}
}

// var testRegistry *parsers.Registry

func TestClassifyRespectsPriorityOfParsers(t *testing.T) {
	logLine := "log"
	excpectResult := &parsers.Result{
		LogType:   "success",
		EventTime: time.Now(),
		JSON:      []byte(`{"p_log_type":"success"}`),
	}
	parserSuccess := testutil.ParserConfig{
		logLine: excpectResult,
	}.Parser()
	parserFail1 := testutil.ParserConfig{
		logLine: errors.New("fail1"),
	}.Parser()
	parserFail2 := testutil.ParserConfig{
		logLine: errors.New("fail2"),
	}.Parser()
	logTypeSuccess := mockLogType("success", parserSuccess)
	logTypeFail1 := mockLogType("failure1", parserFail1)
	logTypeFail2 := mockLogType("failure2", parserFail2)

	classifier := NewClassifier(
		logTypeSuccess,
		logTypeFail1,
		logTypeFail2,
	)

	repetitions := 1000

	expectedResult := &ClassifierResult{
		Events: []*parsers.Result{
			excpectResult,
		},
		LogType: aws.String("success"),
	}
	expectedStats := &ClassifierStats{
		BytesProcessedCount:         uint64(repetitions * len(logLine)),
		LogLineCount:                uint64(repetitions),
		EventCount:                  uint64(repetitions),
		SuccessfullyClassifiedCount: uint64(repetitions),
		ClassificationFailureCount:  0,
	}
	expectedParserStats := parsers.Stats{
		NumBytes:   float64(repetitions * len(logLine)),
		NumLines:   float64(repetitions),
		NumResults: float64(repetitions),
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
	expectedParserStats.TotalTimeSeconds = classifier.ParserStats()["success"].TotalTimeSeconds
	require.Equal(t, expectedParserStats, classifier.ParserStats()["success"])

	parserFail1.RequireLessOrEqualNumberOfCalls(t, "Parse", 1)
	require.Equal(t, classifier.ParserStats()["failure1"], parsers.Stats{})
	require.Equal(t, classifier.ParserStats()["failure2"], parsers.Stats{})
}

func TestClassifyNoMatch(t *testing.T) {
	logLine := "log"
	failingParser := testutil.ParserConfig{
		logLine: errors.New("fail"),
	}.Parser()
	logType := mockLogType("failure", failingParser)
	classifier := NewClassifier(logType)
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
	expectedStatsParser := parsers.Stats{
		NumBytes:  float64(len(logLine)),
		NumErrors: 1,
		NumLines:  1,
	}
	actualStatsParser := classifier.ParserStats()[logType.Name]
	expectedStatsParser.TotalTimeSeconds = actualStatsParser.TotalTimeSeconds
	require.Equal(t, expectedStatsParser, actualStatsParser)
}

func TestClassifyParserPanic(t *testing.T) {
	// uncomment to see the logs produced
	/*
		logger := zap.NewExample()
		defer logger.Sync()
		undo := zap.ReplaceGlobals(logger)
		defer undo()
	*/

	panicParser := &testutil.MockParser{}
	panicParser.On("Parse", mock.Anything).Run(func(args mock.Arguments) { panic("test parser panic") })
	panicLogType := mockLogType("panic", panicParser)
	classifier := NewClassifier(panicLogType)

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
	failingParser1 := testutil.ParserConfig{
		"failure1": ([]*parsers.Result)(nil),
	}.Parser()
	failingParser2 := testutil.ParserConfig{
		"failure2": ([]*parsers.Result)(nil),
	}.Parser()
	logType1 := mockLogType("failure1", failingParser1)
	logType2 := mockLogType("failure2", failingParser2)

	classifier := NewClassifier(logType1, logType2)

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

	failingParser1.RequireLessOrEqualNumberOfCalls(t, "Parse", 1)
	require.Equal(t, classifier.ParserStats()[logType1.Name], parsers.Stats{})
	require.Equal(t, classifier.ParserStats()[logType2.Name], parsers.Stats{})
}
