package destinations

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
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sns"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"

	"github.com/panther-labs/panther/internal/compliance/snapshotlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/internal/log_analysis/notify"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	testLogType = "testLogType"
)

var (
	// fixed reference time
	refTime = (timestamp.RFC3339)(time.Date(2020, 1, 1, 0, 1, 1, 0, time.UTC))
	// expected prefix for s3 paths based on refTime
	expectedS3Prefix = "logs/testlogtype/year=2020/month=01/day=01/hour=00/20200101T000000Z"

	// same as above plus 1 hour
	refTimePlusHour   = (timestamp.RFC3339)((time.Time)(refTime).Add(time.Hour))
	expectedS3Prefix2 = "logs/testlogtype/year=2020/month=01/day=01/hour=01/20200101T010000Z"

	refParseTime  = time.Now()
	resultBuilder = pantherlog.ResultBuilder{
		NextRowID: pantherlog.StaticRowID("row_id"),
		Now:       pantherlog.StaticNow(refParseTime),
	}
)

type mockParser struct {
	parsers.LogParser
	mock.Mock
}

var _ parsers.LogParser = (*mockParser)(nil)

func (m *mockParser) Parse(log string) ([]*parsers.PantherLog, error) {
	args := m.Called(log)
	result := args.Get(0)
	if result == nil {
		return nil, nil
	}
	return result.([]*parsers.PantherLog), nil
}

func (m *mockParser) LogType() string {
	args := m.Called()
	return args.String(0)
}

// testEvent is a test event used for the purposes of this test
type testEvent struct {
	Data string
	parsers.PantherLog
}

type fooEvent struct {
	Time time.Time   `json:"ts" tcodec:"rfc3339" event_time:"true" description:"ts"`
	Foo  null.String `json:"foo" description:"foo"`
}

var refEvent = &fooEvent{
	Time: time.Time(refTime),
	Foo:  null.FromString("bar"),
}

func newTestResult(event interface{}) *parsers.Result {
	if event == nil {
		event = refEvent
	}
	result, _ := resultBuilder.BuildResult(testLogType, event)
	return result
}

func newSimpleTestEvent() *parsers.PantherLog {
	return newTestEvent(testLogType, refTime)
}

func newTestEvent(logType string, eventTime timestamp.RFC3339) *parsers.PantherLog {
	te := &testEvent{
		Data: "test",
	}
	te.SetCoreFields(logType, &eventTime, te)
	return &te.PantherLog
}

func init() {
	common.Config.AwsLambdaFunctionMemorySize = 1024
}

type testS3Destination struct {
	S3Destination
	// back pointers to mocks
	mockSns            *testutils.SnsMock
	mockS3Uploader     *testutils.S3UploaderMock
	mockLatencyCounter *testutils.CounterMock
}

func (td *testS3Destination) AssertExpectations(t *testing.T) {
	td.mockSns.AssertExpectations(t)
	td.mockS3Uploader.AssertExpectations(t)
	td.mockLatencyCounter.AssertExpectations(t)
}

func mockDestination() *testS3Destination {
	mockSns := &testutils.SnsMock{}
	mockS3Uploader := &testutils.S3UploaderMock{}
	mockLatencyCounter := &testutils.CounterMock{}
	return &testS3Destination{
		S3Destination: S3Destination{
			snsTopicArn:         "arn:aws:sns:us-west-2:123456789012:test",
			s3Bucket:            "testbucket",
			snsClient:           mockSns,
			s3Uploader:          mockS3Uploader,
			maxBufferedMemBytes: 10 * 1024 * 1024, // an arbitrary amount enough to hold default test data
			maxDuration:         maxDuration,
			maxBuffers:          maxBuffers,
			maxBufferSize:       uploaderBufferMaxSizeBytes,
			jsonAPI:             common.ConfigForDataLakeWriters(),
			latencyCounter:      mockLatencyCounter,
		},
		mockSns:            mockSns,
		mockS3Uploader:     mockS3Uploader,
		mockLatencyCounter: mockLatencyCounter,
	}
}

func TestSendDataToS3BeforeTerminating(t *testing.T) {
	t.Parallel()

	destination := mockDestination()

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Once()
	destination.mockLatencyCounter.On("Add", mock.Anything).Once()

	testResult := newTestResult(nil)

	// Gzipping the test event
	// Do that now so that the event release does not affect output
	var expectedBytes []byte
	{
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		stream := common.ConfigForDataLakeWriters().BorrowStream(writer)
		stream.WriteVal(testResult)
		require.NoError(t, stream.Flush())
		_, err := writer.Write([]byte("\n"))
		require.NoError(t, err)
		err = writer.Close()
		require.NoError(t, err)
		expectedBytes = buffer.Bytes()
	}
	eventChannel := make(chan *parsers.Result, 1)
	// sending event to buffered channel
	eventChannel <- testResult
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	assert.NoError(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)

	// I am fetching it from the actual request performed to S3 and:
	//1. Verifying the S3 object key is of the correct format
	//2. Verifying the rest of the fields are as expected
	uploadInput := destination.mockS3Uploader.Calls[0].Arguments.Get(0).(*s3manager.UploadInput)

	assert.Equal(t, aws.String("testbucket"), uploadInput.Bucket)
	assert.True(t, strings.HasPrefix(*uploadInput.Key, expectedS3Prefix))

	// Collect what was produced
	bodyBytes, _ := ioutil.ReadAll(uploadInput.Body)
	assert.Equal(t, expectedBytes, bodyBytes)

	// Verifying Sns Publish payload
	publishInput := destination.mockSns.Calls[0].Arguments.Get(0).(*sns.PublishInput)
	expectedS3Notification := notify.NewS3ObjectPutNotification(destination.s3Bucket, *uploadInput.Key,
		len(expectedBytes))

	marshaledExpectedS3Notification, _ := jsoniter.MarshalToString(expectedS3Notification)
	expectedSnsPublishInput := &sns.PublishInput{
		Message:  aws.String(marshaledExpectedS3Notification),
		TopicArn: aws.String("arn:aws:sns:us-west-2:123456789012:test"),
		MessageAttributes: map[string]*sns.MessageAttributeValue{
			"type": {
				StringValue: aws.String("LogData"),
				DataType:    aws.String("String"),
			},
			"id": {
				StringValue: aws.String(testLogType),
				DataType:    aws.String("String"),
			},
		},
	}
	assert.Equal(t, expectedSnsPublishInput, publishInput)
}

func TestSendDataIfTotalMemSizeLimitHasBeenReached(t *testing.T) {
	t.Parallel()

	destination := mockDestination()
	destination.maxBufferedMemBytes = 0 // this will cause each event to trigger a send

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Twice()
	destination.mockLatencyCounter.On("Add", mock.Anything).Twice()

	eventChannel := make(chan *parsers.Result, 2)
	// Use 1 result with `event_time:"true"` struct tag
	eventChannel <- newTestResult(nil)
	// Use 1 result with embedded panther log
	// The second should already cause the S3 object size limits to be exceeded
	// so we expect two objects to be written to s3
	eventChannel <- newSimpleTestEvent().Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	assert.NoError(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)

	// Verify proper buckets were used for both events
	key1 := destination.mockS3Uploader.Calls[0].Arguments.Get(0).(*s3manager.UploadInput).Key
	require.Equal(t, expectedS3Prefix, aws.StringValue(key1)[:len(expectedS3Prefix)])
	key2 := destination.mockS3Uploader.Calls[1].Arguments.Get(0).(*s3manager.UploadInput).Key
	require.Equal(t, expectedS3Prefix, aws.StringValue(key2)[:len(expectedS3Prefix)])
}

func TestSendDataIfBufferSizeLimitHasBeenReached(t *testing.T) {
	t.Parallel()

	destination := mockDestination()
	destination.maxBufferSize = 0 // this will cause each event to trigger a send

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Twice()
	destination.mockLatencyCounter.On("Add", mock.Anything).Twice()

	// sending 2 events to buffered channel
	// The second should already cause the S3 object size limits to be exceeded
	// so we expect two objects to be written to s3
	eventChannel := make(chan *parsers.Result, 2)
	eventChannel <- newSimpleTestEvent().Result()
	eventChannel <- newSimpleTestEvent().Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	assert.NoError(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)
}

func TestSendDataIfTimeLimitHasBeenReached(t *testing.T) {
	t.Parallel()

	destination := mockDestination()
	destination.maxDuration = 50 * time.Millisecond

	const nevents = 4

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Times(nevents)
	destination.mockLatencyCounter.On("Add", mock.Anything).Times(nevents)

	var wg sync.WaitGroup
	eventChannel := make(chan *parsers.Result, nevents)
	go func() {
		defer close(eventChannel)
		for i := 0; i < nevents; i++ {
			wg.Add(1)
			eventChannel <- newSimpleTestEvent().Result()
			// The destination writes events to S3 every 'maxDuration' time.
			// Wait until it has published the message to SNS to send the next message
			wg.Wait()
		}
	}()

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Times(nevents)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Run(func(args mock.Arguments) {
		// Every time we publish a message to SNS,
		// unblock the loop that sends messages to the eventsChannel
		wg.Done()
	}).Times(nevents)

	assert.NoError(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)
}

func TestSendDataToS3FromMultipleLogTypesBeforeTerminating(t *testing.T) {
	t.Parallel()

	destination := mockDestination()

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Twice()
	destination.mockLatencyCounter.On("Add", mock.Anything).Twice()

	eventChannel := make(chan *parsers.Result, 2)
	eventChannel <- newTestEvent("testtype1", refTime).Result()
	eventChannel <- newTestEvent("testtype2", refTime).Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	assert.NoError(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)
}

func TestSendDataToS3FromSameHourBeforeTerminating(t *testing.T) {
	t.Parallel()

	destination := mockDestination()

	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Once()
	destination.mockLatencyCounter.On("Add", mock.Anything).Twice()

	eventChannel := make(chan *parsers.Result, 2)
	// should write both events in 1 file
	eventChannel <- newSimpleTestEvent().Result()
	eventChannel <- newSimpleTestEvent().Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	assert.NoError(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)
}

func TestSendDataToS3FromMultipleHoursBeforeTerminating(t *testing.T) {
	t.Parallel()

	destination := mockDestination()
	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Twice()
	destination.mockLatencyCounter.On("Add", mock.Anything).Twice()

	// should write 2 files with different time partitions
	eventChannel := make(chan *parsers.Result, 2)
	eventChannel <- newTestEvent(testLogType, refTime).Result()
	eventChannel <- newTestEvent(testLogType, refTimePlusHour).Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	assert.NoError(t, runDestination(destination, eventChannel))

	uploadInput := destination.mockS3Uploader.Calls[0].Arguments.Get(0).(*s3manager.UploadInput)
	assert.Equal(t, aws.String("testbucket"), uploadInput.Bucket)
	assert.True(t, strings.HasPrefix(*uploadInput.Key, expectedS3Prefix) ||
		strings.HasPrefix(*uploadInput.Key, expectedS3Prefix2)) // order of results is async

	uploadInput = destination.mockS3Uploader.Calls[1].Arguments.Get(0).(*s3manager.UploadInput)
	assert.Equal(t, aws.String("testbucket"), uploadInput.Bucket)
	assert.True(t, strings.HasPrefix(*uploadInput.Key, expectedS3Prefix) ||
		strings.HasPrefix(*uploadInput.Key, expectedS3Prefix2)) // order of results is async

	destination.AssertExpectations(t)
}

func TestSendDataWhenExceedMaxBuffers(t *testing.T) {
	t.Parallel()

	maxTestDuration := 10 * time.Second

	destination := mockDestination()
	destination.maxBuffers = 1
	destination.maxDuration = 2 * maxTestDuration // make sure that the buffers are not flushed due to time

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Twice()
	destination.mockLatencyCounter.On("Add", mock.Anything).Twice()

	eventChannel := make(chan *parsers.Result, 2)
	// Write the first event to the channel
	eventChannel <- newTestEvent(testLogType, refTime).Result()
	// The next event will be stored in a different buffer than the previous one.
	// Since the max allowed number of buffers in memory is 1, it should trigger writing to S3
	// and sending SNS notification
	eventChannel <- newTestEvent(testLogType+"anothertype", refTime).Result()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).
		Run(func(args mock.Arguments) {
			// When we have written a buffer to S3 and sent notification
			// close the event channel
			close(eventChannel)
		}).Once()

	// Once the channel is closed, the destination will flush to S3 the last buffer
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()

	// Make sure the test doesn't run for more than expected
	timeout := time.After(maxTestDuration)
	done := make(chan bool)
	defer close(done)
	go func() {
		assert.NoError(t, runDestination(destination, eventChannel))
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("Test didn't finish in time")
	case <-done:
	}

	destination.AssertExpectations(t)
}

func TestSendDataFailsIfS3Fails(t *testing.T) {
	t.Parallel()

	destination := mockDestination()

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Once()
	destination.mockLatencyCounter.On("Add", mock.Anything).Once()

	eventChannel := make(chan *parsers.Result, 1)
	eventChannel <- newSimpleTestEvent().Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, errors.New("")).Once()

	assert.Error(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)
}

func TestSendDataFailsIfSnsFails(t *testing.T) {
	t.Parallel()

	destination := mockDestination()

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Once()
	destination.mockLatencyCounter.On("Add", mock.Anything).Once()

	eventChannel := make(chan *parsers.Result, 1)
	eventChannel <- newSimpleTestEvent().Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, errors.New("test"))

	assert.Error(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)
}

func TestBufferSetLargest(t *testing.T) {
	t.Parallel()

	destination := mockDestination()
	destination.mockLatencyCounter.On("With", []string{"LogType", testLogType}).Return(destination.mockLatencyCounter)

	destination.maxBufferSize = 128

	bs := destination.newS3EventBufferSet()
	result := newSimpleTestEvent().Result()
	expectedLargest := bs.getBuffer(result)

	const size = 100
	expectedLargest.bytes = size
	for i := 0; i < size-1; i++ {
		// incr hour so we get new buffers
		result.PantherEventTime = result.PantherEventTime.Add(time.Hour)
		buffer := bs.getBuffer(result)
		buffer.bytes = i
	}
	assert.Equal(t, size, len(bs.set))
	assert.Same(t, bs.removeLargestBuffer(), expectedLargest)

	destination.AssertExpectations(t)
}

func TestSendDataToCloudSecurity(t *testing.T) {
	t.Parallel()

	destination := mockDestination()

	// Mock metrics
	destination.mockLatencyCounter.On("With", mock.Anything).Return(destination.mockLatencyCounter).Once()
	destination.mockLatencyCounter.On("Add", mock.Anything).Once()

	cloudsecEvent := newTestEvent(snapshotlogs.TypeCompliance, refTime)

	eventChannel := make(chan *parsers.Result, 1)
	// sending event to buffered channel
	eventChannel <- cloudsecEvent.Result()
	close(eventChannel)

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	assert.NoError(t, runDestination(destination, eventChannel))

	destination.AssertExpectations(t)

	// I am fetching it from the actual request performed to S3 and:
	//1. Verifying the S3 object key is of the correct format
	//2. Verifying the rest of the fields are as expected
	uploadInput := destination.mockS3Uploader.Calls[0].Arguments.Get(0).(*s3manager.UploadInput)

	assert.Equal(t, aws.String("testbucket"), uploadInput.Bucket)
	expectedPrefix := "cloud_security/compliance_history/year=2020/month=01/day=01/hour=00/20200101T000000Z"

	assert.True(t, strings.HasPrefix(*uploadInput.Key, expectedPrefix))

	// Verifying the SNS notification has the correct DataType
	publishInput := destination.mockSns.Calls[0].Arguments.Get(0).(*sns.PublishInput)
	expectedMessageAttributes := map[string]*sns.MessageAttributeValue{
		"type": {
			StringValue: aws.String("CloudSecurity"),
			DataType:    aws.String("String"),
		},
		"id": {
			StringValue: aws.String(snapshotlogs.TypeCompliance),
			DataType:    aws.String("String"),
		},
	}
	assert.Equal(t, expectedMessageAttributes, publishInput.MessageAttributes)
}

// Runs the destination "SendEvents" function in a goroutine and returns the errors
// reported by it
func runDestination(destination Destination, events chan *parsers.Result) error {
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		destination.SendEvents(events, errChan)
	}()

	var foundErr error
	for err := range errChan {
		foundErr = multierr.Append(foundErr, err)
	}
	return foundErr
}
