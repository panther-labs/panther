package destinations

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"errors"
	"io/ioutil"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
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
)

type mockParser struct {
	parsers.LogParser
	mock.Mock
}

func (m *mockParser) Parse(log string) []*parsers.PantherLog {
	args := m.Called(log)
	result := args.Get(0)
	if result == nil {
		return nil
	}
	return result.([]*parsers.PantherLog)
}

func (m *mockParser) LogType() string {
	args := m.Called()
	return args.String(0)
}

type mockS3 struct {
	s3iface.S3API
	mock.Mock
}

func (m *mockS3) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
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

func registerMockParser(logType string, testEvent *parsers.PantherLog) (testParser *mockParser) {
	testParser = &mockParser{}
	testParser.On("Parse", mock.Anything).Return([]*parsers.PantherLog{testEvent})
	testParser.On("LogType").Return(logType)
	p := registry.DefaultLogParser(testParser, testEvent, "Test "+logType)
	testRegistry.Add(p)
	return
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

var testRegistry = NewTestRegistry()

func initTest() {
	parserRegistry = testRegistry // re-bind as interface
}

type testS3Destination struct {
	S3Destination
	// back pointers to mocks
	mockSns *mockSns
	mockS3  *mockS3
}

func newS3Destination() *testS3Destination {
	mockSns := &mockSns{}
	mockS3 := &mockS3{}
	return &testS3Destination{
		S3Destination: S3Destination{
			snsTopicArn: "arn:aws:sns:us-west-2:123456789012:test",
			s3Bucket:    "testbucket",
			snsClient:   mockSns,
			s3Client:    mockS3,
			maxFileSize: maxFileSize,
			maxDuration: maxDuration,
		},
		mockSns: mockSns,
		mockS3:  mockS3,
	}
}

func TestSendDataToS3BeforeTerminating(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 1)

	testEvent := newSimpleTestEvent()

	// wire it up
	registerMockParser(testLogType, testEvent)

	// sending event to buffered channel
	eventChannel <- testEvent

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)

	// I am fetching it from the actual request performed to S3 and:
	//1. Verifying the S3 object key is of the correct format
	//2. Verifying the rest of the fields are as expected
	putObjectInput := destination.mockS3.Calls[0].Arguments.Get(0).(*s3.PutObjectInput)

	assert.Equal(t, aws.String("testbucket"), putObjectInput.Bucket)
	assert.True(t, strings.HasPrefix(*putObjectInput.Key, expectedS3Prefix))

	// Gzipping the test event
	marshaledEvent, _ := jsoniter.Marshal(testEvent.Event())
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	writer.Write(marshaledEvent) //nolint:errcheck
	writer.Write([]byte("\n"))   //nolint:errcheck
	writer.Close()               //nolint:errcheck
	expectedBytes := buffer.Bytes()

	// Collect what was produced
	bodyBytes, _ := ioutil.ReadAll(putObjectInput.Body)
	assert.Equal(t, expectedBytes, bodyBytes)

	// Verifying Sns Publish payload
	publishInput := destination.mockSns.Calls[0].Arguments.Get(0).(*sns.PublishInput)
	expectedS3Notification := &models.S3Notification{
		S3Bucket:    aws.String("testbucket"),
		S3ObjectKey: putObjectInput.Key,
		Events:      aws.Int(1),
		Bytes:       aws.Int(len(marshaledEvent) + len("\n")),
		Type:        aws.String(models.LogData.String()),
		ID:          aws.String(testLogType),
	}
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

func TestSendDataIfSizeLimitHasBeenReached(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 2)

	testEvent := newSimpleTestEvent()

	// This is the size of a single event
	// We expect this to cause the S3Destination to create two objects in S3
	marshaledEvent, _ := jsoniter.Marshal(testEvent.Event)
	destination.maxFileSize = len(marshaledEvent) + 1

	// wire it up
	registerMockParser(testLogType, testEvent)

	// sending 2 events to buffered channel
	// The second should already cause the S3 object size limits to be exceeded
	// so we expect two objects to be written to s3
	eventChannel <- testEvent
	eventChannel <- testEvent

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataIfTimeLimitHasBeenReached(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 2)

	const nevents = 7
	testEvent := newSimpleTestEvent()
	destination.maxDuration = time.Second / 4

	// wire it up
	registerMockParser(testLogType, testEvent)

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Times(nevents)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Times(nevents)

	// sending nevents to buffered channel
	// The first n-1 should cause the S3 time limit to be exceeded
	// so we expect two objects to be written to s3 from that,
	// the last event is needed to trigger the flush of the second
	go func() {
		for i := 0; i < nevents-1; i++ {
			eventChannel <- testEvent
			time.Sleep(destination.maxDuration + (time.Millisecond * 10)) // give time to for timers to expire
		}
		eventChannel <- testEvent // last event will trigger flush of the last event above
	}()

	runSendEventsTimed(t, destination, eventChannel, false, destination.maxDuration*(nevents+1)) // this blocks

	destination.mockS3.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataToS3FromMultipleLogTypesBeforeTerminating(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 2)

	logType1 := "testtype1"
	testEvent1 := newTestEvent(logType1, refTime)
	logType2 := "testtype2"
	testEvent2 := newTestEvent(logType2, refTime)

	// wire it up
	registerMockParser(logType1, testEvent1)
	registerMockParser(logType2, testEvent2)

	eventChannel <- testEvent1
	eventChannel <- testEvent2

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataToS3FromSameHourBeforeTerminating(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 2)

	// should write 1 file
	testEvent1 := newTestEvent(testLogType, refTime)
	testEvent2 := newTestEvent(testLogType, refTime)

	// wire it up
	registerMockParser(testLogType, testEvent1)

	eventChannel <- testEvent1
	eventChannel <- testEvent2

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Once()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func TestSendDataToS3FromMultipleHoursBeforeTerminating(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 2)

	// should write 2 files with different time partitions
	testEvent1 := newTestEvent(testLogType, refTime)
	testEvent2 := newTestEvent(testLogType, refTimePlusHour)

	// wire it up
	registerMockParser(testLogType, testEvent1)

	eventChannel <- testEvent1
	eventChannel <- testEvent2

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)

	destination.mockS3.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)

	putObjectInput := destination.mockS3.Calls[0].Arguments.Get(0).(*s3.PutObjectInput)
	assert.Equal(t, aws.String("testbucket"), putObjectInput.Bucket)
	assert.True(t, strings.HasPrefix(*putObjectInput.Key, expectedS3Prefix) ||
		strings.HasPrefix(*putObjectInput.Key, expectedS3Prefix2)) // order of results is async

	putObjectInput = destination.mockS3.Calls[1].Arguments.Get(0).(*s3.PutObjectInput)
	assert.Equal(t, aws.String("testbucket"), putObjectInput.Bucket)
	assert.True(t, strings.HasPrefix(*putObjectInput.Key, expectedS3Prefix) ||
		strings.HasPrefix(*putObjectInput.Key, expectedS3Prefix2)) // order of results is async
}

func TestSendDataFailsIfS3Fails(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 1)

	testEvent := newSimpleTestEvent()

	// wire it up
	registerMockParser(testLogType, testEvent)

	eventChannel <- testEvent

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, errors.New("")).Once()

	runSendEvents(t, destination, eventChannel, true)

	destination.mockS3.AssertExpectations(t)
}

func TestSendDataFailsIfSnsFails(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *parsers.PantherLog, 1)

	testEvent := newSimpleTestEvent()

	// wire it up
	registerMockParser(testLogType, testEvent)

	eventChannel <- testEvent

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, errors.New("test"))

	runSendEvents(t, destination, eventChannel, true)

	destination.mockS3.AssertExpectations(t)
	destination.mockSns.AssertExpectations(t)
}

func runSendEvents(t *testing.T, destination Destination, eventChannel chan *parsers.PantherLog, expectErr bool) {
	runSendEventsTimed(t, destination, eventChannel, expectErr, 0)
}

func runSendEventsTimed(t *testing.T, destination Destination, eventChannel chan *parsers.PantherLog,
	expectErr bool, delay time.Duration) {

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

	time.Sleep(delay)
	close(eventChannel) // causes SendEvents() to terminate
	waitSend.Wait()

	close(errChan) // causes err go routines to to terminate
	waitErr.Wait()
}
