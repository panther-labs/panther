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
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
)

// TODO: thorough test when parsers return parsers.Result
func TestClassifyRespectsPriorityOfParsers(t *testing.T) {
	type testEvent struct {
		Foo string `json:"foo"`
	}
	event := testEvent{
		Foo: "bar",
	}
	logLine := "log"
	tm := time.Now().UTC()
	expectResult := &parsers.Result{
		CoreFields: pantherlog.CoreFields{
			PantherLogType:   "success",
			PantherEventTime: tm,
		},
		Event: event,
	}
	parserSuccess := testutil.ParserConfig{
		logLine: expectResult,
	}.Parser()
	parserFail1 := testutil.ParserConfig{
		logLine: errors.New("fail1"),
	}.Parser()
	parserFail2 := testutil.ParserConfig{
		logLine: errors.New("fail2"),
	}.Parser()

	classifier := NewClassifier(map[string]parsers.Interface{
		"success":  parserSuccess,
		"failure1": parserFail1,
		"failure2": parserFail2,
	})

	repetitions := 1000

	expectedResult := &ClassifierResult{
		Matched: true,
		Events: []*parsers.Result{
			expectResult,
		},
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
		result, err := classifier.Classify(logLine)
		if i == 0 {
			// Maps are not ordered, we do not know if first result can miss
			result.NumMiss = 0
		}
		require.NoError(t, err)
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

	parserFail1.RequireLessOrEqualNumberOfCalls(t, "Parse", 1)
	require.Nil(t, classifier.ParserStats()["fail1"])
	require.Nil(t, classifier.ParserStats()["fail2"])
}

func TestClassifyNoMatch(t *testing.T) {
	logLine := "log"
	failingParser := testutil.ParserConfig{
		logLine: errors.New("fail"),
	}.Parser()
	classifier := NewClassifier(map[string]parsers.Interface{
		"failure": failingParser,
	})
	expectedStats := &ClassifierStats{
		BytesProcessedCount:         uint64(len(logLine)),
		LogLineCount:                1,
		EventCount:                  0,
		SuccessfullyClassifiedCount: 0,
		ClassificationFailureCount:  1,
	}

	result, err := classifier.Classify(logLine)
	require.Error(t, err)

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	require.Equal(t, &ClassifierResult{NumMiss: 1}, result)
	failingParser.AssertNumberOfCalls(t, "Parse", 1)
	require.Nil(t, classifier.ParserStats()["failure"])
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
	classifier := NewClassifier(map[string]parsers.Interface{
		"panic": panicParser,
	})

	logLine := "log of death"

	expectedStats := &ClassifierStats{
		BytesProcessedCount:         uint64(len(logLine)),
		LogLineCount:                1,
		EventCount:                  0,
		SuccessfullyClassifiedCount: 0,
		ClassificationFailureCount:  1,
	}

	result, err := classifier.Classify(logLine)
	require.Error(t, err)

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	require.Equal(t, &ClassifierResult{NumMiss: 1}, result)
	panicParser.AssertNumberOfCalls(t, "Parse", 1)
}

func TestClassifyParserReturningEmptyResults(t *testing.T) {
	parser := &testutil.MockParser{}
	parser.On("Parse", mock.Anything).Return([]*parsers.Result{}, nil).Once()
	classifier := NewClassifier(map[string]parsers.Interface{
		"parser": parser,
	})

	logLine := "log of death"

	expectedStats := &ClassifierStats{
		BytesProcessedCount:         uint64(len(logLine)),
		LogLineCount:                1,
		EventCount:                  0,
		SuccessfullyClassifiedCount: 1,
		ClassificationFailureCount:  0,
	}

	result, err := classifier.Classify(logLine)
	require.NoError(t, err)

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	require.Equal(t, &ClassifierResult{
		Events:  []*parsers.Result{},
		Matched: true,
	}, result)
	parser.AssertExpectations(t)
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
	classifier := NewClassifier(map[string]parsers.Interface{
		"failure1": failingParser1,
		"failure2": failingParser2,
	})
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
		result, err := classifier.Classify(logLine)
		require.NoError(t, err)
		require.Equal(t, expectedResult, result)
	}

	// skipping specifically validating the times
	expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	require.Equal(t, expectedStats, classifier.Stats())

	failingParser1.RequireLessOrEqualNumberOfCalls(t, "Parse", 1)
	require.Nil(t, classifier.ParserStats()["failure1"])
	require.Nil(t, classifier.ParserStats()["failure2"])
}
