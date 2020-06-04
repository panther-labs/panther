package processor

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
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/oplog"
)

var (
	parseDelay = time.Millisecond / 2 // time it takes to process a log line
	sendDelay  = time.Millisecond / 2 // time it takes to send event to destination

	testLogType          = "testLogType"
	testLogLine          = "line"
	testLogLines  uint64 = 2000
	testLogEvents        = testLogLines // for these tests they are 1-1

	testBucket      = "testBucket"
	testKey         = "testKey"
	testContentType = "testContentType"
	s3Hint          = &common.S3DataStreamHints{
		Bucket:      testBucket,
		Key:         testKey,
		ContentType: testContentType,
	}
)

type testLog struct {
	logLine string
	parsers.PantherLog
}

func newTestLog() *pantherlog.Result {
	refTime := (timestamp.RFC3339)(time.Date(2020, 1, 1, 0, 1, 1, 0, time.UTC))
	log := testLog{
		logLine: testLogLine,
	}
	log.SetCoreFields(testLogType, &refTime, &log)
	result, _ := log.Result()
	return result
}

func TestProcess(t *testing.T) {
	destination := (&testDestination{}).standardMock()

	dataStream := makeDataStream()
	p := NewProcessor(dataStream)
	mockClassifier := &testClassifier{}
	p.classifier = mockClassifier

	mockStats := &classification.ClassifierStats{
		ClassifyTimeMicroseconds:    1,
		BytesProcessedCount:         (testLogLines) * uint64(len(testLogLine)),
		LogLineCount:                testLogLines,
		EventCount:                  testLogLines,
		SuccessfullyClassifiedCount: testLogLines,
		ClassificationFailureCount:  0,
	}
	mockParserStats := map[string]*classification.ParserStats{
		testLogType: {
			ParserTimeMicroseconds: 1,
			BytesProcessedCount:    (testLogLines) * uint64(len(testLogLine)),
			LogLineCount:           testLogLines,
			EventCount:             testLogLines,
			LogType:                testLogType,
		},
	}

	mockClassifier.standardMocks(mockStats, mockParserStats)

	newProcessorFunc := func(*common.DataStream) *Processor { return p }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err := process(streamChan, destination, newProcessorFunc)
	require.NoError(t, err)
	require.Equal(t, testLogEvents, destination.nEvents)
}

func TestProcessDataStreamError(t *testing.T) {
	logs := mockLogger()

	destination := (&testDestination{}).standardMock()
	dataStream := makeBadDataStream() // failure to read data, never hits classifier
	p := NewProcessor(dataStream)
	mockClassifier := &testClassifier{}
	p.classifier = mockClassifier

	// classifier never gets called
	mockStats := &classification.ClassifierStats{}
	mockParserStats := map[string]*classification.ParserStats{}

	mockClassifier.standardMocks(mockStats, mockParserStats)

	newProcessorFunc := func(*common.DataStream) *Processor { return p }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err := process(streamChan, destination, newProcessorFunc)
	require.Error(t, err)

	// confirm error log is as expected
	expectedLogMesg := common.OpLogNamespace + ":" + common.OpLogComponent + ":" + operationName
	expectedLog := observer.LoggedEntry{

		Entry: zapcore.Entry{
			Level:   zapcore.ErrorLevel,
			Message: expectedLogMesg,
		},
		Context: []zapcore.Field{
			// custom
			zap.Any(statsKey, *mockStats),

			// error
			zap.Error(errors.Wrap(errFailingReader, "failed to ReadString()")), // from run()

			// standard
			zap.String("namespace", common.OpLogNamespace),
			zap.String("component", common.OpLogComponent),
			zap.String("operation", operationName),
			zap.String("status", oplog.Failure),
			zap.Time("startOp", p.operation.StartTime),
			zap.Duration("opTime", p.operation.EndTime.Sub(p.operation.StartTime)),
			zap.Time("endOp", p.operation.EndTime),
		},
	}

	// the error will be different due to annotation, so check each field, just compare strings for error
	actualLog := logs.FilterMessage(expectedLogMesg).AllUntimed()[0]
	assertLogEqual(t, expectedLog, actualLog)
}

func TestProcessDataStreamErrorNoChannelBuffers(t *testing.T) {
	ParsedEventBufferSize = 0 // ensure we work when event channel is blocking
	TestProcessDataStreamError(t)
}

func TestProcessDestinationError(t *testing.T) {
	// error in Send events
	sendEventsErr := errors.New("fail SendEvents")
	destination := &testDestination{}
	destination.On("SendEvents", mock.Anything, mock.Anything).Return().Run(func(args mock.Arguments) {
		errChan := args.Get(1).(chan error)
		errChan <- sendEventsErr
		for range args.Get(0).(chan *pantherlog.Result) {
		} // must drain q
	})

	dataStream := makeDataStream()
	p := NewProcessor(dataStream)
	mockClassifier := &testClassifier{}
	p.classifier = mockClassifier

	mockStats := &classification.ClassifierStats{
		ClassifyTimeMicroseconds:    1,
		BytesProcessedCount:         (testLogLines) * uint64(len(testLogLine)),
		LogLineCount:                testLogLines,
		EventCount:                  testLogLines,
		SuccessfullyClassifiedCount: testLogLines,
		ClassificationFailureCount:  0,
	}
	mockParserStats := map[string]*classification.ParserStats{
		testLogType: {
			ParserTimeMicroseconds: 1,
			BytesProcessedCount:    (testLogLines) * uint64(len(testLogLine)),
			LogLineCount:           testLogLines,
			EventCount:             testLogLines,
			LogType:                testLogType,
		},
	}

	mockClassifier.standardMocks(mockStats, mockParserStats)

	newProcessorFunc := func(*common.DataStream) *Processor { return p }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err := process(streamChan, destination, newProcessorFunc)
	require.Error(t, err)
}

func TestProcessDestinationErrorNoChannelBuffers(t *testing.T) {
	ParsedEventBufferSize = 0 // ensure we work when event channel is blocking
	TestProcessDestinationError(t)
}

// test we properly log parse failures so we can see which file and where in the file there was a failure
func TestProcessClassifyFailure(t *testing.T) {
	logs := mockLogger()

	destination := (&testDestination{}).standardMock()
	dataStream := makeDataStream()
	p := NewProcessor(dataStream)
	mockClassifier := &testClassifier{}
	p.classifier = mockClassifier

	mockStats := &classification.ClassifierStats{
		ClassifyTimeMicroseconds:    1,
		BytesProcessedCount:         (testLogLines) * uint64(len(testLogLine)),
		LogLineCount:                testLogLines,
		EventCount:                  testLogLines - 1,
		SuccessfullyClassifiedCount: testLogLines - 1,
		ClassificationFailureCount:  1, // this is the failure
	}
	mockParserStats := map[string]*classification.ParserStats{
		testLogType: {
			ParserTimeMicroseconds: 1,
			BytesProcessedCount:    (testLogLines - 1) * uint64(len(testLogLine)),
			LogLineCount:           testLogLines - 1,
			EventCount:             testLogLines - 1,
			LogType:                testLogType,
		},
	}

	// first one fails
	mockClassifier.On("Classify", mock.Anything).Return(&classification.ClassifierResult{
		Events:  []*pantherlog.Result{},
		LogType: nil,
	}).Once()
	mockClassifier.On("Classify", mock.Anything).Return(&classification.ClassifierResult{
		Events:  []*pantherlog.Result{newTestLog()},
		LogType: &testLogType,
	})
	mockClassifier.On("Stats", mock.Anything).Return(mockStats)
	mockClassifier.On("ParserStats", mock.Anything).Return(mockParserStats)

	newProcessorFunc := func(*common.DataStream) *Processor { return p }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err := process(streamChan, destination, newProcessorFunc)
	require.NoError(t, err)

	actual := logs.AllUntimed()
	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{
				Level:   zapcore.WarnLevel,
				Message: common.OpLogNamespace + ":" + common.OpLogComponent + ":" + operationName,
			},
			Context: []zapcore.Field{
				// custom
				zap.Uint64("lineNum", actual[0].ContextMap()["lineNum"].(uint64)), // this one varies due to mock, skip in validation
				zap.String("bucket", testBucket),
				zap.String("key", testKey),

				// error
				zap.Error(errors.New("failed to classify log line")),

				// standard
				zap.String("namespace", common.OpLogNamespace),
				zap.String("component", common.OpLogComponent),
				zap.String("operation", operationName),
				zap.String("status", oplog.Failure),
				zap.Time("startOp", p.operation.StartTime),
				zap.Duration("opTime", actual[0].ContextMap()["opTime"].(time.Duration)), // this one we can't calc and will skip in validation
			},
		},
		{
			Entry: zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Message: common.OpLogNamespace + ":" + common.OpLogComponent + ":" + operationName,
			},
			Context: []zapcore.Field{
				// custom
				zap.Any(statsKey, *mockStats),

				// standard
				zap.String("namespace", common.OpLogNamespace),
				zap.String("component", common.OpLogComponent),
				zap.String("operation", operationName),
				zap.String("status", oplog.Success),
				zap.Time("startOp", p.operation.StartTime),
				zap.Duration("opTime", p.operation.EndTime.Sub(p.operation.StartTime)),
				zap.Time("endOp", p.operation.EndTime),
			},
		},
		{
			Entry: zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Message: common.OpLogNamespace + ":" + common.OpLogComponent + ":" + operationName,
			},
			Context: []zapcore.Field{
				// custom
				zap.Any(statsKey, *mockParserStats[testLogType]),

				// standard
				zap.String("namespace", common.OpLogNamespace),
				zap.String("component", common.OpLogComponent),
				zap.String("operation", operationName),
				zap.String("status", oplog.Success),
				zap.Time("startOp", p.operation.StartTime),
				zap.Duration("opTime", p.operation.EndTime.Sub(p.operation.StartTime)),
				zap.Time("endOp", p.operation.EndTime),
			},
		},
	}
	require.Equal(t, len(expected), len(actual))
	for i := range expected {
		assertLogEqual(t, expected[i], actual[i])
	}
}

// deals with the error package inserting line numbers into errors
func assertLogEqual(t *testing.T, expected, actual observer.LoggedEntry) {
	for k, v := range expected.ContextMap() {
		if k == "errorVerbose" { // has code line numbers that need to be removed to compare
			expectedError := fmt.Sprintf("%v", v)
			expectedError = expectedError[strings.LastIndex(expectedError, ":"):] // just compare msg after last ':'
			actualError := fmt.Sprintf("%v", actual.ContextMap()[k])
			actualError = actualError[strings.LastIndex(actualError, ":"):] // just compare msg after last ':'
			assert.Equal(t, expectedError, actualError)
		} else {
			assert.Equal(t, v, actual.ContextMap()[k],
				fmt.Sprintf("%s for\n\texpected:%#v\n\tactual:%#v", k, expected, actual))
		}
	}
}

type testDestination struct {
	destinations.Destination
	mock.Mock
	nEvents uint64
}

// mocks override
func (d *testDestination) SendEvents(parsedEventChannel chan *pantherlog.Result, errChan chan error) {
	d.MethodCalled("SendEvents", parsedEventChannel, errChan) // execute mocks
}

func (d *testDestination) standardMock() *testDestination {
	d.On("SendEvents", mock.Anything, mock.Anything).Return().Run(func(args mock.Arguments) {
		for range args.Get(0).(chan *pantherlog.Result) { // simulate reading
			time.Sleep(sendDelay) // wait to give processor time to send events
			d.nEvents++
		}
	})
	return d
}

type testClassifier struct {
	classification.ClassifierAPI
	mock.Mock
}

func (c *testClassifier) Classify(log string) *classification.ClassifierResult {
	args := c.Called(log)
	return args.Get(0).(*classification.ClassifierResult)
}

func (c *testClassifier) Stats() *classification.ClassifierStats {
	args := c.Called()
	return args.Get(0).(*classification.ClassifierStats)
}

func (c *testClassifier) ParserStats() map[string]*classification.ParserStats {
	args := c.Called()
	return args.Get(0).(map[string]*classification.ParserStats)
}

// mocks for normal processing
func (c *testClassifier) standardMocks(cStats *classification.ClassifierStats, pStats map[string]*classification.ParserStats) {
	c.On("Classify", mock.Anything).Return(&classification.ClassifierResult{
		Events:  []*pantherlog.Result{newTestLog()},
		LogType: &testLogType,
	}).After(parseDelay)
	c.On("Stats", mock.Anything).Return(cStats)
	c.On("ParserStats", mock.Anything).Return(pStats)
}

func makeDataStream() (dataStream *common.DataStream) {
	testData := make([]string, testLogLines)
	for i := uint64(0); i < testLogLines; i++ {
		testData[i] = testLogLine
	}
	dataStream = &common.DataStream{
		Reader:  strings.NewReader(strings.Join(testData, "\n")),
		LogType: &testLogType,
		Hints:   common.DataStreamHints{S3: s3Hint},
	}
	return
}

var errFailingReader = errors.New("failed")

type failingReader struct{}

func (fr *failingReader) Read(b []byte) (int, error) {
	return 0, errFailingReader
}

// returns a dataStream that will cause the parse to fail
func makeBadDataStream() (dataStream *common.DataStream) {
	testLogType := "testLogType"
	dataStream = &common.DataStream{
		Reader:  &failingReader{},
		LogType: &testLogType,
	}
	return
}

// replace global logger with an in-memory observer for tests.
func mockLogger() *observer.ObservedLogs {
	core, mockLog := observer.New(zap.InfoLevel)
	zap.ReplaceGlobals(zap.New(core))
	return mockLog
}
