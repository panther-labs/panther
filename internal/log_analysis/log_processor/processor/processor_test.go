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
	"context"
	"fmt"
	"io"
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

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor/logstream"
	"github.com/panther-labs/panther/pkg/metrics"
	"github.com/panther-labs/panther/pkg/oplog"
)

var (
	parseDelay   = time.Millisecond / 2 // time it takes to process a log line
	sendDelay    = time.Millisecond / 2 // time it takes to send event to destination
	testRegistry = logtypes.Must("testLogTypes", logtypes.Config{
		Name:         testLogType,
		Description:  "Test log type",
		ReferenceURL: "-",
		Schema: &struct {
			LogLine string `json:"logLine" description:"log line"`
		}{},
		NewParser: pantherlog.FactoryFunc(func(_ interface{}) (parsers.Interface, error) {
			return testutil.AlwaysFailParser(errors.New("fail parser")), nil
		}),
	})
	testResolver = logtypes.LocalResolver(testRegistry)

	testLogType          = "testLogType"
	testLogLine          = "line"
	testLogLines  uint64 = 2000
	testLogEvents        = testLogLines // for these tests they are 1-1

	testBucket      = "testBucket"
	testSourceID    = "testSource"
	testSourceLabel = "testSourceLabel"
	testKey         = "testKey"
)

type testLog struct {
	logLine string
	parsers.PantherLog
}

func newTestLog() *parsers.Result {
	refTime := (timestamp.RFC3339)(time.Date(2020, 1, 1, 0, 1, 1, 0, time.UTC))
	log := testLog{
		logLine: testLogLine,
	}
	log.SetCoreFields(testLogType, &refTime, &log)
	return log.Result()
}

func TestProcess(t *testing.T) {
	destination := (&testDestination{}).standardMock()

	dataStream := makeDataStream()
	f := NewFactory(testResolver)
	p, err := f(dataStream)
	require.NoError(t, err)
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

	newProcessorFunc := func(*common.DataStream) (*Processor, error) { return p, nil }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err = Process(context.Background(), streamChan, destination, newProcessorFunc)
	require.NoError(t, err)
	require.Equal(t, testLogEvents, destination.nEvents, "wrong number of events %d != %d", testLogEvents, destination.nEvents)

	// ensure the closer was called
	assert.True(t, dataStream.Closer.(*dummyCloser).closed)
}

func TestProcessDataStreamError(t *testing.T) {
	logs := mockLogger()

	destination := (&testDestination{}).standardMock()
	dataStream := makeBadDataStream() // failure to read data, never hits classifier
	f := NewFactory(testResolver)
	p, err := f(dataStream)
	require.NoError(t, err)
	mockClassifier := &testClassifier{}
	p.classifier = mockClassifier

	// classifier never gets called
	mockStats := &classification.ClassifierStats{}
	mockParserStats := map[string]*classification.ParserStats{}

	mockClassifier.standardMocks(mockStats, mockParserStats)

	newProcessorFunc := func(*common.DataStream) (*Processor, error) { return p, nil }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err = Process(context.Background(), streamChan, destination, newProcessorFunc)
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
			zap.Error(errors.Wrap(errFailingReader, "failed to read log line")), // from run()

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

	// ensure the closer was called
	assert.True(t, dataStream.Closer.(*dummyCloser).closed)
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
		for range args.Get(0).(chan *parsers.Result) {
		} // must drain q
	})

	dataStream := makeDataStream()
	f := NewFactory(testResolver)
	p, err := f(dataStream)
	require.NoError(t, err)
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

	newProcessorFunc := func(*common.DataStream) (*Processor, error) { return p, nil }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err = Process(context.Background(), streamChan, destination, newProcessorFunc)
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
	f := NewFactory(testResolver)
	p, err := f(dataStream)
	require.NoError(t, err)
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
	mockClassifier.On("Classify", mock.Anything).Return(&classification.ClassifierResult{}, errFailingReader).Once()
	mockClassifier.On("Classify", mock.Anything).Return(&classification.ClassifierResult{
		Events:  []*parsers.Result{newTestLog()},
		Matched: true,
	}, nil)
	mockClassifier.On("Stats", mock.Anything).Return(mockStats)
	mockClassifier.On("ParserStats", mock.Anything).Return(mockParserStats)

	newProcessorFunc := func(*common.DataStream) (*Processor, error) { return p, nil }
	streamChan := make(chan *common.DataStream, 1)
	streamChan <- dataStream
	close(streamChan)
	err = Process(context.Background(), streamChan, destination, newProcessorFunc)
	require.NoError(t, err)

	actual := logs.AllUntimed()
	embeddedMetric := metrics.EmbeddedMetric{
		CloudWatchMetrics: []metrics.MetricDirectiveObject{
			{
				Namespace:  "Panther",
				Dimensions: []metrics.DimensionSet{{"LogType"}},
				Metrics: []metrics.Metric{
					{
						Name: "BytesProcessed",
						Unit: metrics.UnitBytes,
					},
					{
						Name: "EventsProcessed",
						Unit: metrics.UnitCount,
					},
					{
						Name: "CombinedLatency",
						Unit: metrics.UnitMilliseconds,
					},
				},
			},
		},
		Timestamp: time.Duration(p.operation.EndTime.UnixNano()).Milliseconds(),
	}

	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{
				Level:   zapcore.WarnLevel,
				Message: common.OpLogNamespace + ":" + common.OpLogComponent + ":" + operationName,
			},
			Context: []zapcore.Field{
				// custom
				zap.Uint64("lineNum", actual[0].ContextMap()["lineNum"].(uint64)), // this one varies due to mock, skip in validation
				zap.String("sourceId", testSourceID),
				zap.String("sourceLabel", testSourceLabel),
				zap.String("s3Bucket", testBucket),
				zap.String("s3ObjectKey", testKey),

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
		{
			Entry: zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Message: "metric",
			},
			Context: []zapcore.Field{
				zap.String("LogType", testLogType),
				zap.Uint64("BytesProcessed", 7996),
				zap.Uint64("EventsProcessed", 1999),
				zap.Uint64("CombinedLatency", 0),
				zap.Any("_aws", embeddedMetric),
			},
		},
		{
			Entry: zapcore.Entry{
				Level:   zapcore.InfoLevel,
				Message: common.OpLogNamespace + ":" + common.OpLogComponent + ":" + "readS3Object",
			},
			Context: []zapcore.Field{
				zap.String("namespace", common.OpLogNamespace),
				zap.String("component", common.OpLogComponent),
				zap.String("operation", "readS3Object"),
				zap.String("bucket", testBucket),
				zap.String("key", testKey),
				zap.Int64("size", 0),
				zap.String("sourceID", testSourceID),
			},
		},
	}
	require.Equal(t, len(expected), len(actual))

	for i := range expected {
		// This thing checks metrics logs...
		if i == len(expected)-2 {
			assert.Equal(t, expected[i].Entry.Level, actual[i].Entry.Level)
			assert.Equal(t, expected[i].Entry.Message, actual[i].Entry.Message)
			require.Equal(t, len(expected[i].Context), len(actual[i].Context))
			for j := range expected[i].Context {
				assert.Equal(t, expected[i].Context[j].Key, actual[i].Context[j].Key)
				if actual[i].Context[j].Key == "_aws" {
					actualTyped := actual[i].Context[j].Interface.(metrics.EmbeddedMetric)
					actualTyped.Timestamp = p.operation.EndTime.UnixNano() / metrics.NanosecondsPerMillisecond
					assert.Equal(t, expected[i].Context[j].Interface, actualTyped)
					continue
				}
				assert.Equal(t, expected[i].Context[j].Interface, actual[i].Context[j].Interface)
				assert.Equal(t, expected[i].Context[j].String, actual[i].Context[j].String)
				assert.Equal(t, expected[i].Context[j].Integer, actual[i].Context[j].Integer)
			}
			continue
		}
		assertLogEqual(t, expected[i], actual[i])
	}

	// ensure the closer was called
	assert.True(t, dataStream.Closer.(*dummyCloser).closed)
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
				"%s for\n\texpected:%#v\n\tactual:%#v", k, expected.ContextMap(), actual.ContextMap())
		}
	}
}

type testDestination struct {
	destinations.Destination
	mock.Mock
	nEvents uint64
}

// mocks override
func (d *testDestination) SendEvents(parsedEventChannel chan *parsers.Result, errChan chan error) {
	d.MethodCalled("SendEvents", parsedEventChannel, errChan) // execute mocks
}

func (d *testDestination) standardMock() *testDestination {
	d.On("SendEvents", mock.Anything, mock.Anything).Return().Run(func(args mock.Arguments) {
		for range args.Get(0).(chan *parsers.Result) { // simulate reading
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

func (c *testClassifier) Classify(log string) (*classification.ClassifierResult, error) {
	args := c.Called(log)
	return args.Get(0).(*classification.ClassifierResult), args.Error(1)
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
		Events:  []*parsers.Result{newTestLog()},
		Matched: true,
	}, nil).After(parseDelay)
	c.On("Stats", mock.Anything).Return(cStats)
	c.On("ParserStats", mock.Anything).Return(pStats)
}

func makeDataStream() *common.DataStream {
	testData := make([]string, testLogLines)
	for i := uint64(0); i < testLogLines; i++ {
		testData[i] = testLogLine
	}
	reader := strings.NewReader(strings.Join(testData, "\n"))
	return &common.DataStream{
		Stream:      logstream.NewLineStream(reader, 4096),
		Closer:      &dummyCloser{},
		Source:      testSource,
		S3ObjectKey: testKey,
		S3Bucket:    testBucket,
	}
}

type dummyCloser struct {
	io.Reader
	closed bool
}

func (dc *dummyCloser) Close() error {
	dc.closed = true
	if rc, ok := dc.Reader.(io.ReadCloser); ok {
		return rc.Close()
	}
	return nil
}

var errFailingReader = errors.New("failed")

type failingReader struct{}

func (fr *failingReader) Read(_ []byte) (int, error) {
	return 0, errFailingReader
}

var testSource = &models.SourceIntegration{
	SourceIntegrationMetadata: models.SourceIntegrationMetadata{
		IntegrationID:    testSourceID,
		IntegrationLabel: testSourceLabel,
		IntegrationType:  models.IntegrationTypeAWS3,
		S3Bucket:         testBucket,
		S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "", Logtypes: []string{testLogType}}},
	},
}

// returns a dataStream that will cause the parse to fail
func makeBadDataStream() *common.DataStream {
	return &common.DataStream{
		Stream: logstream.NewLineStream(&failingReader{}, 4096),
		Closer: &dummyCloser{},
		Source: testSource,
	}
}

// replace global logger with an in-memory observer for tests.
func mockLogger() *observer.ObservedLogs {
	core, mockLog := observer.New(zap.InfoLevel)
	zap.ReplaceGlobals(zap.New(core))
	return mockLog
}
