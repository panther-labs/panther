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
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

const (
	// s3ObjectKeyFormat represents the format of the S3 object key
	// It has 3 parts:
	// 1. The key prefix 2. Timestamp in format `s3ObjectTimestampFormat` 3. UUID4
	s3ObjectKeyFormat = "%s%s-%s.json.gz"

	// The timestamp format in the S3 objects with second precision: yyyyMMddTHHmmssZ
	S3ObjectTimestampFormat = "20060102T150405Z"

	logDataTypeAttributeName = "type"
	logTypeAttributeName     = "id"

	messageAttributeDataType = "String"

	//  maximum time to hold an s3 buffer in memory (controls latency of rules engine which processes this output
	maxDuration = 2 * time.Minute

	bytesPerMB                  = 1024 * 1024
	defaultMaxS3BufferSizeBytes = 50 * bytesPerMB
)

var (
	maxS3BufferSizeBytes = defaultMaxS3BufferSizeBytes // the largest we let any single buffer get (var so we can set in tests)

	newLineDelimiter = []byte("\n")

	memUsedAtStartupMB int // set in init(), used to size memory buffers for S3 write
)

func init() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memUsedAtStartupMB = (int)(memStats.Sys/(bytesPerMB)) + 1
}

func CreateS3Destination(logTypes *pantherlog.Registry) Destination {
	return &S3Destination{
		s3Uploader:          common.S3Uploader,
		snsClient:           common.SnsClient,
		s3Bucket:            common.Config.ProcessedDataBucket,
		snsTopicArn:         common.Config.SnsTopicARN,
		maxBufferedMemBytes: maxS3BufferMemUsageBytes(common.Config.AwsLambdaFunctionMemorySize),
		maxDuration:         maxDuration,
		logTypes:            logTypes,
	}
}

// the largest we let total size of compressed output buffers get before calling sendData() to write to S3 in bytes
// NOTE: this presumes processing 1 file at a time
func maxS3BufferMemUsageBytes(lambdaSizeMB int) uint64 {
	const (
		/*
					NOTE:
					  "More specifically CloudTrail will collect logs for 5 mins or until the max file size of 45MB has been reached.
					  An important thing worth noting is that these logs get compressed before being sent to S3, once the file size
					  limit is met or the time limit has been exceeded"
				    Because CT files are "document" JSON and all on 1 line we currently need to read ALL the uncompressed data into memory.
			        FIXME: we should switch to streaming JSON reader
					Below we set the lower bound on memory to be 45MB * 4 (because we convert all the records and parse) plus some for overhead
		*/
		largestAllInMemFileMB     = 45
		processingExpansionFactor = 4
		memoryFootprint           = largestAllInMemFileMB * processingExpansionFactor
		minimumScratchMemMB       = 5 // how much overhead is needed to process a file
	)
	maxBufferUsageMB := lambdaSizeMB - memUsedAtStartupMB - memoryFootprint - minimumScratchMemMB
	if maxBufferUsageMB < 5 {
		panic(fmt.Sprintf("available memory too small for log processing, increase lambda size from %dMB", lambdaSizeMB))
	}

	return (uint64)(maxBufferUsageMB) * bytesPerMB // to bytes
}

// S3Destination sends normalized events to S3
type S3Destination struct {
	s3Uploader s3manageriface.UploaderAPI
	snsClient  snsiface.SNSAPI
	// s3Bucket is the s3Bucket where the data will be stored
	s3Bucket string
	// snsTopic is the SNS Topic ARN where we will send the notification
	// when we store new data in S3
	snsTopicArn string
	// thresholds for ejection
	maxBufferedMemBytes uint64 // max will hold in buffers before ejection
	maxDuration         time.Duration
	logTypes            *pantherlog.Registry
}

// SendEvents stores events in S3.
// It continuously reads events from outputChannel, groups them in batches per log type
// and stores them in the appropriate S3 path. If the method encounters an error
// it writes an error to the errorChannel and continues until channel is closed (skipping events).
// The sendData() method is called as go routine to allow processing to continue and hide network latency.
func (destination *S3Destination) SendEvents(parsedEventChannel chan *pantherlog.Result, errChan chan error) {
	// used to flush expired buffers
	flushExpired := time.NewTicker(destination.maxDuration)
	defer flushExpired.Stop()

	// use a single go routine for safety/back pressure when writing to s3 concurrently with buffer accumulation
	var sendWaitGroup sync.WaitGroup
	sendChan := make(chan *s3EventBuffer) // unbuffered for back pressure (we want only 1 sendData() in flight)
	sendWaitGroup.Add(1)
	go func() {
		for buffer := range sendChan {
			destination.sendData(buffer, errChan)
		}
		sendWaitGroup.Done()
	}()

	// accumulate results gzip'd in a buffer
	failed := false // set to true on error and loop will drain channel
	bufferSet := newS3EventBufferSet()
	eventsProcessed := 0
	zap.L().Debug("starting to read events from channel")
	for event := range parsedEventChannel {
		if failed { // drain channel
			continue
		}

		// Check if any buffer has data for longer than maxDuration
		select {
		case <-flushExpired.C:
			now := time.Now()                                  // NOTE: not the same as the tick time which can be older
			_ = bufferSet.apply(func(b *s3EventBuffer) error { // does not return an error
				if now.Sub(b.createTime) >= destination.maxDuration {
					bufferSet.removeBuffer(b) // bufferSet is not thread safe, do this here
					sendChan <- b
				}
				return nil
			})
		default: // makes select non-blocking
		}

		buffer := bufferSet.getBuffer(event)

		err := bufferSet.addEvent(buffer, event.JSON)
		if err != nil {
			failed = true
			errChan <- err
			continue
		}

		// Check if buffer is bigger than threshold for a single buffer
		if buffer.bytes >= maxS3BufferSizeBytes {
			bufferSet.removeBuffer(buffer) // bufferSet is not thread safe, do this here
			sendChan <- buffer
		}

		// Check if bufferSet is bigger than threshold for total memory usage
		if bufferSet.totalBufferedMemBytes >= destination.maxBufferedMemBytes {
			largestBuffer := bufferSet.largestBuffer()
			if largestBuffer == nil { // this should NEVER happen since we exceeded threshold
				zap.L().Error("bufferSet error",
					zap.Error(errors.New("non-empty bufferSet does not have buffer")))
			} else {
				bufferSet.removeBuffer(largestBuffer) // bufferSet is not thread safe, do this here
				sendChan <- buffer
			}
		}

		eventsProcessed++
	}

	if failed {
		zap.L().Debug("failed, returning after draining parsedEventsChannel")
	}

	zap.L().Debug("output channel closed, sending last events")
	// If the channel has been closed send the buffered messages before terminating
	_ = bufferSet.apply(func(buffer *s3EventBuffer) error {
		bufferSet.removeBuffer(buffer) // bufferSet is not thread safe, do this here
		sendChan <- buffer
		return nil
	})

	close(sendChan)
	sendWaitGroup.Wait() // wait until all writes to s3 are done

	zap.L().Debug("finished sending s3 files", zap.Int("events", eventsProcessed))
}

// sendData puts data in S3 and sends notification to SNS
func (destination *S3Destination) sendData(buffer *s3EventBuffer, errChan chan error) {
	if buffer.events == 0 { // skip empty buffers
		return
	}

	var (
		err           error
		contentLength int64
		key           string
	)

	operation := common.OpLogManager.Start("sendData", common.OpLogS3ServiceDim)
	defer func() {
		operation.Stop()
		operation.Log(err,
			// s3 dim info
			zap.Int64("contentLength", contentLength),
			zap.String("bucket", destination.s3Bucket),
			zap.String("key", key))
	}()

	key, err = destination.getS3ObjectKey(buffer.logType, buffer.hour)
	if err != nil {
		errChan <- err
		return
	}

	payload, err := buffer.read()
	if err != nil {
		errChan <- err
		return
	}

	contentLength = int64(len(payload)) // for logging above

	if _, err := destination.s3Uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(destination.s3Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(payload),
	}); err != nil {
		errChan <- errors.Wrap(err, "S3Upload")
		return
	}

	err = destination.sendSNSNotification(key, buffer) // if send fails we fail whole operation
	if err != nil {
		errChan <- err
	}
}

func (destination *S3Destination) sendSNSNotification(key string, buffer *s3EventBuffer) error {
	var err error
	operation := common.OpLogManager.Start("sendSNSNotification", common.OpLogSNSServiceDim)
	defer func() {
		operation.Stop()
		operation.Log(err,
			zap.String("topicArn", destination.snsTopicArn))
	}()

	s3Notification := models.NewS3ObjectPutNotification(destination.s3Bucket, key, buffer.bytes)

	marshalledNotification, err := jsoniter.MarshalToString(s3Notification)
	if err != nil {
		err = errors.Wrap(err, "failed to marshal notification")
		return err
	}

	input := &sns.PublishInput{
		TopicArn: aws.String(destination.snsTopicArn),
		Message:  aws.String(marshalledNotification),
		MessageAttributes: map[string]*sns.MessageAttributeValue{
			logDataTypeAttributeName: {
				StringValue: aws.String(models.LogData.String()),
				DataType:    aws.String(messageAttributeDataType),
			},
			logTypeAttributeName: {
				StringValue: aws.String(buffer.logType),
				DataType:    aws.String(messageAttributeDataType),
			},
		},
	}
	if _, err = destination.snsClient.Publish(input); err != nil {
		err = errors.Wrap(err, "failed to send notification to topic")
		return err
	}

	return err
}

func (destination *S3Destination) getS3ObjectKey(logType string, timestamp time.Time) (string, error) {
	typ := destination.logTypes.Get(logType)
	if typ == nil {
		return "", errors.Errorf(`unknown log type %q`, logType)
	}
	meta := typ.GlueTableMetadata()
	return fmt.Sprintf(s3ObjectKeyFormat,
		meta.GetPartitionPrefix(timestamp.UTC()), // get the path to store the data in S3
		timestamp.Format(S3ObjectTimestampFormat),
		uuid.New().String(),
	), nil
}

// s3BufferSet is a group of buffers associated with hour time bins, pointing to maps logtype->s3EventBuffer
type s3EventBufferSet struct {
	totalBufferedMemBytes uint64 // managed by addEvent() and removeBuffer()
	set                   map[time.Time]map[string]*s3EventBuffer
}

func newS3EventBufferSet() *s3EventBufferSet {
	return &s3EventBufferSet{
		set: make(map[time.Time]map[string]*s3EventBuffer),
	}
}

func (bs *s3EventBufferSet) getBuffer(event *pantherlog.Result) *s3EventBuffer {
	// bin by hour (this is our partition size)
	hour := event.EventTime.Truncate(time.Hour)

	logTypeToBuffer, ok := bs.set[hour]
	if !ok {
		logTypeToBuffer = make(map[string]*s3EventBuffer)
		bs.set[hour] = logTypeToBuffer
	}

	logType := event.LogType
	buffer, ok := logTypeToBuffer[logType]
	if !ok {
		buffer = newS3EventBuffer(logType, hour)
		logTypeToBuffer[logType] = buffer
	}

	return buffer
}

func (bs *s3EventBufferSet) addEvent(buffer *s3EventBuffer, event []byte) error {
	eventBytes, err := buffer.addEvent(event)
	bs.totalBufferedMemBytes += (uint64)(eventBytes)
	return err
}

func (bs *s3EventBufferSet) removeBuffer(buffer *s3EventBuffer) {
	logTypeToBuffer, ok := bs.set[buffer.hour]
	if !ok {
		return
	}
	bs.totalBufferedMemBytes -= (uint64)(buffer.bytes)
	delete(logTypeToBuffer, buffer.logType)
}

func (bs *s3EventBufferSet) largestBuffer() (largestBuffer *s3EventBuffer) {
	var maxBufferSize int
	_ = bs.apply(func(buffer *s3EventBuffer) error { // we do not return any errors
		if buffer.bytes > maxBufferSize {
			maxBufferSize = buffer.bytes
			largestBuffer = buffer
		}
		return nil
	})
	return largestBuffer
}

func (bs *s3EventBufferSet) apply(f func(buffer *s3EventBuffer) error) error {
	for _, logTypeToBuffer := range bs.set {
		for _, buffer := range logTypeToBuffer {
			err := f(buffer)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// s3EventBuffer is a group of events of the same type
// that will be stored in the same S3 object
type s3EventBuffer struct {
	logType    string
	buffer     *bytes.Buffer
	writer     *gzip.Writer
	bytes      int
	events     int
	hour       time.Time // the event time bin
	createTime time.Time // used to expire buffer
}

func newS3EventBuffer(logType string, hour time.Time) *s3EventBuffer {
	buffer := &bytes.Buffer{}
	writer := gzip.NewWriter(buffer)
	return &s3EventBuffer{
		logType:    logType,
		buffer:     buffer,
		writer:     writer,
		hour:       hour,
		createTime: time.Now(), // used with time.Tick() to check expiration ... no need for UTC()
	}
}

// addEvent adds new data to the s3EventBuffer, return bytes added and error
func (b *s3EventBuffer) addEvent(event []byte) (int, error) {
	startBufferSize := b.buffer.Len()

	_, err := b.writer.Write(event)
	if err != nil {
		err = errors.Wrap(err, "failed to add data to buffer %s")
		return 0, err
	}

	// Adding new line delimiter
	_, err = b.writer.Write(newLineDelimiter)
	if err != nil {
		err = errors.Wrap(err, "failed to add data to buffer")
		return 0, err
	}

	b.bytes = b.buffer.Len() // size of compressed data minus gzip buffer (that's ok we just use this for memory pressure)
	b.events++
	return b.bytes - startBufferSize, nil
}

func (b *s3EventBuffer) read() ([]byte, error) {
	// get last buffered data into buffer
	if err := b.writer.Close(); err != nil {
		return nil, errors.Wrap(err, "close failed in buffer read()")
	}

	data := b.buffer.Bytes()
	b.bytes = len(data) // true final size after flushing gzip buffer

	// clear to make GC more effective
	b.buffer.Reset()
	b.buffer = nil
	b.writer = nil

	return data, nil
}
