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
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/internal/log_analysis/notify"
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

type mockS3ManagerUploader struct {
	s3manageriface.UploaderAPI
	mock.Mock
}

func (m *mockS3ManagerUploader) Upload(input *s3manager.UploadInput, f ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error) {
	args := m.Called(input, f)
	return args.Get(0).(*s3manager.UploadOutput), args.Error(1)
}

type mockSns struct {
	snsiface.SNSAPI
	mock.Mock
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

func (m *mockSns) Publish(input *sns.PublishInput) (*sns.PublishOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sns.PublishOutput), args.Error(1)
}

func initTest() {
	common.Config.AwsLambdaFunctionMemorySize = 1024
	maxS3BufferSizeBytes = defaultMaxS3BufferSizeBytes
}

type testS3Destination struct {
	S3Destination
	// back pointers to mocks
	mockSns        *mockSns
	mockS3Uploader *mockS3ManagerUploader
}

func newS3Destination() *testS3Destination {
	mockSns := &mockSns{}
	mockS3Uploader := &mockS3ManagerUploader{}
	return &testS3Destination{
		S3Destination: S3Destination{
			snsTopicArn:         "arn:aws:sns:us-west-2:123456789012:test",
			s3Bucket:            "testbucket",
			snsClient:           mockSns,
			s3Uploader:          mockS3Uploader,
			maxBufferedMemBytes: 10 * 1024 * 1024, // an arbitrary amount enough to hold default test data
			maxDuration:         maxDuration,
			maxBuffers:          maxBuffers,
			jsonAPI:             common.ConfigForDataLakeWriters(),
		},
		mockSns:        mockSns,
		mockS3Uploader: mockS3Uploader,
	}
}

func TestSendDataToS3BeforeTerminating(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.Result, 1)

	testResult := newTestResult(nil)

	// Gzipping the test event
	// Do that now so that the event release does not affect output
	var expectedBytes []byte
	//nolint:errcheck
	{
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		stream := common.ConfigForDataLakeWriters().BorrowStream(writer)
		stream.WriteVal(testResult)
		require.NoError(t, stream.Flush())
		_, _ = writer.Write([]byte("\n"))
		_ = writer.Close()
		expectedBytes = buffer.Bytes()
	}
	// sending event to buffered channel
	eventChannel <- testResult

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)

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
				StringValue: aws.String(models.LogData.String()),
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
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.Result, 2)

	// Use 1 result with `event_time:"true"` struct tag
	testResult1 := newTestResult(nil)
	// Use 1 result with embedded panther log
	testResult2 := newSimpleTestEvent().Result()

	// wire it up
	destination.maxBufferedMemBytes = 0 // this will cause each event to trigger a send

	// sending 2 events to buffered channel
	// The second should already cause the S3 object size limits to be exceeded
	// so we expect two objects to be written to s3
	eventChannel <- testResult1
	eventChannel <- testResult2

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)

	// Verify proper buckets were used for both events
	key1 := destination.mockS3Uploader.Calls[0].Arguments.Get(0).(*s3manager.UploadInput).Key
	require.Equal(t, expectedS3Prefix, aws.StringValue(key1)[:len(expectedS3Prefix)])
	key2 := destination.mockS3Uploader.Calls[1].Arguments.Get(0).(*s3manager.UploadInput).Key
	require.Equal(t, expectedS3Prefix, aws.StringValue(key2)[:len(expectedS3Prefix)])
}

func TestSendDataIfBufferSizeLimitHasBeenReached(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.Result, 2)

	testEvent := newSimpleTestEvent()
	testResult := testEvent.Result()

	maxS3BufferSizeBytes = 0 // this will cause each event to trigger a send

	// sending 2 events to buffered channel
	// The second should already cause the S3 object size limits to be exceeded
	// so we expect two objects to be written to s3
	eventChannel <- testResult
	eventChannel <- testResult

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataIfTimeLimitHasBeenReached(t *testing.T) {
	initTest()

	eventChannel := make(chan *parsers.Result, 2)
	doneChannel := make(chan bool, 1)

	const nevents = 7
	testEvent := newSimpleTestEvent()
	testResult := testEvent.Result()
	destination := newS3Destination()
	destination.maxDuration = time.Second / 4

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Times(nevents)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Times(nevents)

	// sending nevents to buffered channel
	// The first n-1 should cause the S3 time limit to be exceeded
	// so we expect two objects to be written to s3 from that,
	// the last event is needed to trigger the flush of the previous
	go func() {
		for i := 0; i < nevents-1; i++ {
			eventChannel <- testResult
			time.Sleep(destination.maxDuration + (time.Millisecond * 10)) // give time to for timers to expire
		}
		eventChannel <- testResult // last event will trigger flush of the last event above
		doneChannel <- true
	}()

	runSendEventsSignaled(t, destination, eventChannel, false, doneChannel) // this blocks

	close(doneChannel)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataToS3FromMultipleLogTypesBeforeTerminating(t *testing.T) {
	initTest()

	eventChannel := make(chan *parsers.Result, 2)

	logType1 := "testtype1"
	testEvent1 := newTestEvent(logType1, refTime)
	testResult1 := testEvent1.Result()
	logType2 := "testtype2"
	testEvent2 := newTestEvent(logType2, refTime)
	testResult2 := testEvent2.Result()

	// wire it up
	destination := newS3Destination()

	eventChannel <- testResult1
	eventChannel <- testResult2

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataToS3FromSameHourBeforeTerminating(t *testing.T) {
	initTest()

	eventChannel := make(chan *parsers.Result, 2)

	// should write 1 file
	testEvent1 := newTestEvent(testLogType, refTime)
	testResult1 := testEvent1.Result()
	testEvent2 := newTestEvent(testLogType, refTime)
	testResult2 := testEvent2.Result()

	// wire it up
	destination := newS3Destination()

	eventChannel <- testResult1
	eventChannel <- testResult2

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataToS3FromMultipleHoursBeforeTerminating(t *testing.T) {
	initTest()

	eventChannel := make(chan *parsers.Result, 2)

	// should write 2 files with different time partitions
	testEvent1 := newTestEvent(testLogType, refTime)
	testResult1 := testEvent1.Result()
	testEvent2 := newTestEvent(testLogType, refTimePlusHour)
	testResult2 := testEvent2.Result()

	// wire it up
	destination := newS3Destination()

	eventChannel <- testResult1
	eventChannel <- testResult2

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)

	uploadInput := destination.mockS3Uploader.Calls[0].Arguments.Get(0).(*s3manager.UploadInput)
	assert.Equal(t, aws.String("testbucket"), uploadInput.Bucket)
	assert.True(t, strings.HasPrefix(*uploadInput.Key, expectedS3Prefix) ||
		strings.HasPrefix(*uploadInput.Key, expectedS3Prefix2)) // order of results is async

	uploadInput = destination.mockS3Uploader.Calls[1].Arguments.Get(0).(*s3manager.UploadInput)
	assert.Equal(t, aws.String("testbucket"), uploadInput.Bucket)
	assert.True(t, strings.HasPrefix(*uploadInput.Key, expectedS3Prefix) ||
		strings.HasPrefix(*uploadInput.Key, expectedS3Prefix2)) // order of results is async
}

func TestSendDataWhenExceedMaxBuffers(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.Result, 1)

	testEvent := newSimpleTestEvent()
	testResult := testEvent.Result()

	destination.maxBuffers = 0 // this will cause all events to be written immediately

	// sending 1 event to buffered channel and the max buffers is 0, so it will immediately send the buffer to s3
	eventChannel <- testResult

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataFailsIfS3Fails(t *testing.T) {
	initTest()

	eventChannel := make(chan *parsers.Result, 1)

	testEvent := newSimpleTestEvent()
	testResult := testEvent.Result()

	// wire it up
	destination := newS3Destination()

	eventChannel <- testResult

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, errors.New("")).Once()

	runSendEvents(t, destination, eventChannel, true)

	destination.mockS3Uploader.AssertExpectations(t)
}

func TestSendDataFailsIfSnsFails(t *testing.T) {
	initTest()

	eventChannel := make(chan *parsers.Result, 1)

	testEvent := newSimpleTestEvent()
	testResult := testEvent.Result()

	// wire it up
	destination := newS3Destination()

	eventChannel <- testResult

	destination.mockS3Uploader.On("Upload", mock.Anything, mock.Anything).Return(&s3manager.UploadOutput{}, nil)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, errors.New("test"))

	runSendEvents(t, destination, eventChannel, true)

	destination.mockS3Uploader.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestBufferSetLargest(t *testing.T) {
	const size = 100
	event := newTestEvent(testLogType, refTime)
	bs := newS3EventBufferSet(&S3Destination{jsonAPI: common.ConfigForDataLakeWriters()}, 128)
	result := event.Result()
	expectedLargest := bs.getBuffer(result)
	expectedLargest.bytes = size
	for i := 0; i < size-1; i++ {
		// incr hour so we get new buffers
		result.PantherEventTime = result.PantherEventTime.Add(time.Hour)
		buffer := bs.getBuffer(result)
		buffer.bytes = i
	}
	assert.Equal(t, size, len(bs.set))
	require.Same(t, bs.largestBuffer(), expectedLargest)
}

func runSendEvents(t *testing.T, destination Destination, eventChannel chan *parsers.Result, expectErr bool) {
	runSendEventsSignaled(t, destination, eventChannel, expectErr, nil)
}

func runSendEventsSignaled(t *testing.T, destination Destination, eventChannel chan *parsers.Result,
	expectErr bool, doneChan chan bool) {

	var waitErr sync.WaitGroup
	errChan := make(chan error, 128)
	waitErr.Add(1)
	if expectErr {
		go func() {
			var foundErr error
			for err := range errChan {
				foundErr = err
			}
			assert.Error(t, foundErr)
			waitErr.Done()
		}()
	} else {
		go func() {
			for err := range errChan {
				assert.NoError(t, err)
			}
			waitErr.Done()
		}()
	}

	var waitSend sync.WaitGroup
	waitSend.Add(1)
	go func() {
		destination.SendEvents(eventChannel, errChan)
		waitSend.Done()
	}()

	if doneChan != nil {
		<-doneChan
	}
	close(eventChannel) // causes SendEvents() to terminate
	waitSend.Wait()

	close(errChan) // causes err go routines to to terminate
	waitErr.Wait()
}
