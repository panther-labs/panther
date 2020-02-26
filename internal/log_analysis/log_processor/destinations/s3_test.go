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
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

type mockParser struct {
	parsers.LogParser
	mock.Mock
}

func (m *mockParser) Parse(log string) []interface{} {
	args := m.Called(log)
	result := args.Get(0)
	if result == nil {
		return nil
	}
	return result.([]interface{})
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
	data string
}

func (m *mockSns) Publish(input *sns.PublishInput) (*sns.PublishOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sns.PublishOutput), args.Error(1)
}

func registerMockParser(logType string, testEvent *testEvent) (testParser *mockParser) {
	testParser = &mockParser{}
	testParser.On("Parse", mock.Anything).Return([]interface{}{testEvent})
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
	mockSns  *mockSns
	mockS3   *mockS3
}

func newS3Destination() *testS3Destination {
	mockSns := &mockSns{}
	mockS3 := &mockS3{}
	return &testS3Destination{
		S3Destination: S3Destination{
			snsTopicArn:          "arn:aws:sns:us-west-2:123456789012:test",
			s3Bucket:             "testbucket",
			snsClient:            mockSns,
			s3Client:             mockS3,
		},
		mockSns:  mockSns,
		mockS3:   mockS3,
	}
}

func TestSendDataToS3BeforeTerminating(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *common.ParsedEvent, 1)

	testEvent := testEvent{data: "test"}

	// wire it up
	logType := "testtype"
	parsedEvent := &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType,
	}
	registerMockParser(logType, &testEvent)

	// sending event to buffered channel
	eventChannel <- parsedEvent

	marshalledEvent, _ := jsoniter.Marshal(parsedEvent.Event)

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil)

	runSendEvents(t, destination, eventChannel, false)

	// There is no way to know the key of the S3 object since we are generating it based on time
	// I am fetching it from the actual request performed to S3 and:
	//1. Verifying the S3 object key is of the correct format
	//2. Verifying the rest of the fields are as expected
	putObjectInput := destination.mockS3.Calls[0].Arguments.Get(0).(*s3.PutObjectInput)
	// Gzipping the test event
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)

	writer.Write(marshalledEvent) //nolint:errcheck
	writer.Write([]byte("\n"))    //nolint:errcheck
	writer.Close()                //nolint:errcheck

	bodyBytes, _ := ioutil.ReadAll(putObjectInput.Body)
	require.Equal(t, aws.String("testbucket"), putObjectInput.Bucket)
	require.Equal(t, buffer.Bytes(), bodyBytes)

	// Verifying Sns Publish payload
	publishInput := destination.mockSns.Calls[0].Arguments.Get(0).(*sns.PublishInput)
	expectedS3Notification := &models.S3Notification{
		S3Bucket:    aws.String("testbucket"),
		S3ObjectKey: putObjectInput.Key,
		Events:      aws.Int(1),
		Bytes:       aws.Int(len(marshalledEvent) + len("\n")),
		Type:        aws.String(models.LogData.String()),
		ID:          aws.String("testtype"),
	}
	marshalledExpectedS3Notification, _ := jsoniter.MarshalToString(expectedS3Notification)
	expectedSnsPublishInput := &sns.PublishInput{
		Message:  aws.String(marshalledExpectedS3Notification),
		TopicArn: aws.String("arn:aws:sns:us-west-2:123456789012:test"),
		MessageAttributes: map[string]*sns.MessageAttributeValue{
			"type": {
				StringValue: aws.String(models.LogData.String()),
				DataType:    aws.String("String"),
			},
			"id": {
				StringValue: aws.String("testtype"),
				DataType:    aws.String("String"),
			},
		},
	}
	require.Equal(t, expectedSnsPublishInput, publishInput)
}

func TestSendDataIfSizeLimitHasBeenReached(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *common.ParsedEvent, 2)

	testEvent := testEvent{data: "test"}

	// wire it up
	logType := "testtype"
	registerMockParser(logType, &testEvent)

	// sending 2 events to buffered channel
	// The second should already cause the S3 object size limits to be exceeded
	// so we expect two objects to be written to s3
	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType,
	}
	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType,
	}

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	// This is the size of a single event
	// We expect this to cause the S3Destination to create two objects in S3
	maxFileSize = 3

	runSendEvents(t, destination, eventChannel, false)
}

func TestSendDataIfTimeLimitHasBeenReached(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *common.ParsedEvent, 2)

	testEvent := testEvent{data: "test"}

	// wire it up
	logType := "testtype"
	registerMockParser(logType, &testEvent)

	// sending 2 events to buffered channel
	// The second should already cause the S3 object size limits to be exceeded
	// so we expect two objects to be written to s3
	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType,
	}
	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType,
	}

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	// We expect this to cause the S3Destination to create two objects in S3
	maxDuration = 1 * time.Nanosecond

	runSendEvents(t, destination, eventChannel, false)
}

func TestSendDataToS3FromMultipleLogTypesBeforeTerminating(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *common.ParsedEvent, 2)

	testEvent := testEvent{data: "test"}

	// wire it up
	logType1 := "testtype1"
	registerMockParser(logType1, &testEvent)
	logType2 := "testtype2"
	registerMockParser(logType2, &testEvent)

	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType1,
	}
	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType2,
	}

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil).Twice()
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Twice()

	runSendEvents(t, destination, eventChannel, false)
}

func TestSendDataFailsIfS3Fails(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *common.ParsedEvent, 1)

	testEvent := testEvent{data: "test"}

	// wire it up
	logType := "testtype"
	registerMockParser(logType, &testEvent)

	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType,
	}

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, errors.New("")).Twice()

	runSendEvents(t, destination, eventChannel, true)
}

func TestSendDataFailsIfSnsFails(t *testing.T) {
	initTest()

	destination := newS3Destination()
	eventChannel := make(chan *common.ParsedEvent, 1)

	testEvent := testEvent{data: "test"}

	// wire it up
	logType := "testtype"
	registerMockParser(logType, &testEvent)

	eventChannel <- &common.ParsedEvent{
		Event:   testEvent,
		LogType: logType,
	}

	destination.mockS3.On("PutObject", mock.Anything).Return(&s3.PutObjectOutput{}, nil)
	destination.mockSns.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, errors.New("test"))

	runSendEvents(t, destination, eventChannel, true)
}

func runSendEvents(t *testing.T, destination Destination, eventChannel chan *common.ParsedEvent, expectErr bool) {
	errChan := make(chan error)

	if expectErr {
		go func() {
			var foundErr error
			for err := range errChan {
				foundErr = err
			}
			require.Error(t, foundErr)
		}()
	} else {
		go func() {
			var foundErr error
			for err := range errChan {
				foundErr = err
			}
			require.NoError(t, foundErr)
		}()
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		destination.SendEvents(eventChannel, errChan)
		wg.Done()
	}()
	close(eventChannel) // causes SendEvents() to terminate
	wg.Wait()
	close(errChan)
}
