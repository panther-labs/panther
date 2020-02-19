package oplog

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const (
	testNamespace = "panther"
	testComponent = "logprocessor"
	testOperation = "upload"
	testDim       = "s3"
)

var (
	startTime = time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
	endTime   = startTime.Add(time.Second)
	dimension = zap.String("service", testDim)
	testOp    = NewManager(testNamespace, testComponent).Start(testOperation, dimension)
)

func init() {
	testOp.Stop()
	// for consistency reset to fixed times
	testOp.StartTime = startTime
	testOp.EndTime = endTime
}

// Replace global logger with an in-memory observer for tests.
func mockLogger() *observer.ObservedLogs {
	core, mockLog := observer.New(zap.DebugLevel)
	zap.ReplaceGlobals(zap.New(core))
	return mockLog
}

func expectedLog(level zapcore.Level, status string, err error, customField zapcore.Field) []observer.LoggedEntry {
	if err != nil {
		return []observer.LoggedEntry{
			{
				Entry: zapcore.Entry{Level: level, Message: testNamespace + ":" + testComponent + ":" + testOperation},
				Context: []zapcore.Field{

					customField,

					zap.Error(err),

					// standard
					zap.String("namespace", testNamespace),
					zap.String("component", testComponent),
					zap.String("operation", testOperation),
					zap.String("status", status),
					zap.Time("startOp", startTime),
					zap.Duration("opTime", endTime.Sub(startTime)),
					zap.Time("endOp", endTime),

					// dimensions
					dimension,
				},
			},
		}
	}
	return []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: level, Message: testNamespace + ":" + testComponent + ":" + testOperation},
			Context: []zapcore.Field{

				customField,

				// standard
				zap.String("namespace", testNamespace),
				zap.String("component", testComponent),
				zap.String("operation", testOperation),
				zap.String("status", status),
				zap.Time("startOp", startTime),
				zap.Duration("opTime", endTime.Sub(startTime)),
				zap.Time("endOp", endTime),

				// dimensions
				dimension,
			},
		},
	}
}

func TestOperationLog(t *testing.T) {
	customField := zap.Int64("eventCount", 10)

	// success
	logs := mockLogger()
	testOp.Log(nil, customField)
	expected := expectedLog(zapcore.InfoLevel, Success, nil, zap.Int64("eventCount", 10))
	assert.Equal(t, expected, logs.AllUntimed())

	// fail
	logs = mockLogger()
	err := errors.New("some error")
	testOp.Log(err, customField)
	expected = expectedLog(zapcore.ErrorLevel, Failure, err, zap.Int64("eventCount", 10))
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestOperationLogSuccess(t *testing.T) {
	logs := mockLogger()
	customField := zap.Int64("eventCount", 10)
	testOp.LogSuccess(customField)
	expected := expectedLog(zapcore.InfoLevel, Success, nil, zap.Int64("eventCount", 10))
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestOperationLogWarn(t *testing.T) {
	logs := mockLogger()
	customField := zap.Int64("eventCount", 10)
	err := fmt.Errorf("warning will robinson! ")
	testOp.LogWarn(err, customField)
	expected := expectedLog(zapcore.WarnLevel, Failure, err, customField)
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestOperationLogError(t *testing.T) {
	logs := mockLogger()
	customField := zap.Int64("eventCount", 10)
	err := fmt.Errorf("omg! ")
	testOp.LogError(err, customField)
	expected := expectedLog(zapcore.ErrorLevel, Failure, err, customField)
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestOperationLogBeforeStop(t *testing.T) {
	logs := mockLogger()
	delay := time.Millisecond
	op := NewManager(testNamespace, testComponent).Start(testOperation)
	time.Sleep(delay) // need because this is so fast
	op.LogWarn(errors.New("something happened mid operation"))
	require.Equal(t, 1, len(logs.FilterMessage(op.zapMsg()).All())) // should be just one like this
	require.Nil(t, logs.FilterMessage(op.zapMsg()).All()[0].ContextMap()["endOp"])
	dur := (logs.FilterMessage(op.zapMsg()).All()[0].ContextMap()["opTime"]).(time.Duration)
	require.True(t, dur >= delay)
}

func TestOperationWithMemStats(t *testing.T) {
	logs := mockLogger()
	op := NewManager(testNamespace, testComponent).Start(testOperation).WithMemStats().WithMemUsed(10)
	require.NotNil(t, op.StartMemStats)
	op.Stop()
	op.LogSuccess()
	logMap := logs.FilterMessage(op.zapMsg()).All()[0].ContextMap()
	assert.NotNil(t, logMap["sysSizeMB"])
	assert.NotNil(t, logMap["heapSizeMB"])
	assert.NotNil(t, logMap["heapChangeMB"])
	assert.NotNil(t, logMap["gcPercent"])
	assert.NotNil(t, logMap["gcPauseMilliseconds"])
	assert.NotNil(t, logMap["gcCycles"])
	assert.NotNil(t, logMap["percentMemUsed"])
}
