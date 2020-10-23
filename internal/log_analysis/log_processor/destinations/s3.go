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
	"path"
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
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/process"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	// The timestamp layout used in the S3 object key filename part with second precision: yyyyMMddTHHmmssZ
	S3ObjectTimestampLayout = "20060102T150405Z"

	logDataTypeAttributeName = "type"
	logTypeAttributeName     = "id"

	messageAttributeDataType = "String"

	//  maximum time to hold an s3 buffer in memory (controls latency of rules engine which processes this output)
	maxDuration = 2 * time.Minute

	// maximum number of buffers in memory (if exceeded buffers are flushed)
	maxBuffers = 256

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

func CreateS3Destination(jsonAPI jsoniter.API) Destination {
	if jsonAPI == nil {
		jsonAPI = jsoniter.ConfigDefault
	}
	return &S3Destination{
		s3Uploader:          common.S3Uploader,
		snsClient:           common.SnsClient,
		s3Bucket:            common.Config.ProcessedDataBucket,
		snsTopicArn:         common.Config.SnsTopicARN,
		maxBufferedMemBytes: maxS3BufferMemUsageBytes(common.Config.AwsLambdaFunctionMemorySize),
		maxDuration:         maxDuration,
		maxBuffers:          maxBuffers,
		jsonAPI:             jsonAPI,
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
		minimumScratchMemMB       = 5 // how much overhead is needed to process
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
	maxBuffers          int
	jsonAPI             jsoniter.API
}

// SendEvents stores events in S3.
// It continuously reads events from parsedEventChannel, groups them in batches per log type
// and stores them in the appropriate S3 path. If the method encounters an error
// it writes an error to the errorChannel and continues until channel is closed (skipping events).
// The sendData() method is called as go routine to allow processing to continue and hide network latency.
func (destination *S3Destination) SendEvents(parsedEventChannel chan *parsers.Result, errChan chan error) {
	// used to flush expired buffers
	flushExpired := time.NewTicker(destination.maxDuration)
	defer flushExpired.Stop()

	// use a single go routine for safety/back pressure when writing to s3 concurrently with buffer accumulation
	var sendWaitGroup sync.WaitGroup
	// FIXME: We risk a panic causing a memory leak by never exiting the write goroutine (see below).
	sendChan := make(chan *s3EventBuffer) // unbuffered for back pressure (we want only 1 sendData() in flight)

	sendWaitGroup.Add(1)
	go func() {
		// Make sure a panic does not prevent SendEvents from exiting
		defer sendWaitGroup.Done()
		for buffer := range sendChan {
			destination.sendData(buffer, errChan)
		}
	}()

	// accumulate results gzip'd in a buffer
	failed := false // set to true on error and loop will drain channel
	bufferSet := newS3EventBufferSet(destination, maxS3BufferSizeBytes)
	eventsProcessed := 0
	zap.L().Debug("starting to read events from channel")
	for event := range parsedEventChannel {
		if failed { // drain channel
			continue
		}

		// Check if any buffer has data for longer than maxDuration
		select {
		case <-flushExpired.C:
			now := time.Now()                                          // NOTE: not the same as the tick time which can be older
			_ = bufferSet.apply(func(b *s3EventBuffer) (bool, error) { // does not return an error
				if now.Sub(b.createTime) >= destination.maxDuration {
					bufferSet.removeBuffer(b) // bufferSet is not thread safe, do this here
					sendChan <- b
				}
				return false, nil
			})
		default: // makes select non-blocking
		}
		sendBuffers, err := bufferSet.writeEvent(event)
		if err != nil {
			failed = true
			zap.L().Debug(`aborting log processing: failed to write event`, zap.Error(err), zap.String(`logType`, event.PantherLogType))
			errChan <- errors.Wrapf(err, "failed to write event %s", event.PantherLogType)
			continue
		}
		// buffers needs flushing
		for _, buf := range sendBuffers {
			sendChan <- buf
		}

		eventsProcessed++
	}

	if failed {
		zap.L().Debug("failed, returning after draining parsedEventsChannel")
	}

	zap.L().Debug("output channel closed, sending last events")
	// If the channel has been closed send the buffered messages before terminating
	_ = bufferSet.apply(func(buffer *s3EventBuffer) (bool, error) {
		bufferSet.removeBuffer(buffer) // bufferSet is not thread safe, do this here
		sendChan <- buffer
		return false, nil
	})

	// FIXME: closing the channel here is appropriate but we risk a panic leaving the write goroutine open forever.
	// causing a memory leak. To fix this we need to have the reading of results in a goroutine and keep the writing here.
	// We need to wrap the read loop in a separate function and synchronize with defer close(sendChan).
	// Write failures should also abort the whole log processing so this is more complex than it looks.
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

	key = getS3ObjectKey(buffer.logType, buffer.hour)
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
		Bucket: &destination.s3Bucket,
		Key:    &key,
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

	s3Notification := process.NewS3ObjectPutNotification(destination.s3Bucket, key, buffer.bytes)

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

// getS3ObjectKey builds the S3 object key for storing a partition file of processed logs.
func getS3ObjectKey(logType string, timestamp time.Time) string {
	dbPrefix := awsglue.GetDataPrefix(awsglue.LogProcessingDatabaseName)
	tblName := awsglue.GetTableName(logType)
	partitionPrefix := awsglue.GlueTableHourly.PartitionPathS3(timestamp)
	filename := fmt.Sprintf("%s-%s.json.gz",
		timestamp.Format(S3ObjectTimestampLayout),
		uuid.New(),
	)
	return path.Join(dbPrefix, tblName, partitionPrefix, filename)
}

// s3BufferSet is a group of buffers associated with hour time bins, pointing to maps logtype->s3EventBuffer
type s3EventBufferSet struct {
	totalBufferedMemBytes uint64 // managed by addEvent() and removeBuffer()
	set                   map[time.Time]map[string]*s3EventBuffer
	stream                *jsoniter.Stream
	maxBuffers            int
	maxBufferSize         int
	maxTotalSize          uint64
}

func newS3EventBufferSet(destination *S3Destination, maxTotalSize int) *s3EventBufferSet {
	const initialBufferSize = 8192
	// Stream will be a buffered stream
	stream := jsoniter.NewStream(destination.jsonAPI, nil, initialBufferSize)
	return &s3EventBufferSet{
		stream:        stream,
		set:           make(map[time.Time]map[string]*s3EventBuffer),
		maxBuffers:    destination.maxBuffers,
		maxBufferSize: maxTotalSize,
		maxTotalSize:  destination.maxBufferedMemBytes,
	}
}

// writeEvent adds event to the bufferSet, if it returns a non nil buffer slice then these  buffers need to be written to s3
func (bs *s3EventBufferSet) writeEvent(event *parsers.Result) (sendBuffers []*s3EventBuffer, err error) {
	// HERE BE DRAGONS
	// We need to first serialize the event to JSON for events that only set the event time via `event_time:"true"` tag.
	// This includes custom logs and other simple struct-based events.
	stream := bs.stream
	stream.Reset(nil)
	stream.WriteVal(event)
	// By now if the event has event time defined then event.PantherEventTime will be a non-zero value
	err, stream.Error = stream.Error, nil
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize event to JSON")
	}
	// Just in case something was amiss elsewhere `getBuffer` checks again and uses PantherParseTime and Time.Now() as fallbacks.
	buf := bs.getBuffer(event)
	if buf == nil {
		return nil, errors.New(`could not resolve a buffer for the event`)
	}
	n, err := buf.addEvent(stream.Buffer())
	bs.totalBufferedMemBytes += uint64(n)
	if err != nil {
		return nil, err
	}
	// Check if bufferSet has too many entries
	if len(bs.set) > bs.maxBuffers {
		// The hope is most of the flushed buffers were done updating (as events often come roughly in time order)
		bufferReduction := bs.maxBuffers / 2
		removeBuffers := func(buffer *s3EventBuffer) (bool, error) {
			if len(sendBuffers) >= bufferReduction {
				return true, nil // stop the apply() function
			}
			bs.removeBuffer(buffer) // bufferSet is not thread safe, do this here
			sendBuffers = append(sendBuffers, buffer)
			return false, nil
		}
		_ = bs.apply(removeBuffers) // ignore error, not used in removeBuffers()
	}
	// Check if buffer is bigger than threshold for a single buffer
	if buf.bytes >= bs.maxBufferSize {
		bs.removeBuffer(buf) // bufferSet is not thread safe, do this here
		sendBuffers = append(sendBuffers, buf)
	}
	// Check if bufferSet is bigger than threshold for total memory usage
	if bs.totalBufferedMemBytes >= bs.maxTotalSize {
		if largestBuffer := bs.largestBuffer(); largestBuffer != nil {
			bs.removeBuffer(largestBuffer) // bufferSet is not thread safe, do this here
			sendBuffers = append(sendBuffers, largestBuffer)
		}
	}

	return sendBuffers, nil
}

func (bs *s3EventBufferSet) getBuffer(event *parsers.Result) *s3EventBuffer {
	// Make sure we have a valid time to set the event partition
	// If the event had no event time we use PantherParseTime and time.Now as fallbacks
	eventTime := event.PantherEventTime
	if eventTime.IsZero() {
		eventTime = event.PantherParseTime
		if eventTime.IsZero() {
			return nil
		}
	}
	// bin by hour (this is our partition size)
	// We convert to UTC here so truncation does not affect the partition in the weird half-hour timezones if for
	// some reason (bug) a non-UTC timestamp got through.
	hour := eventTime.UTC().Truncate(time.Hour)

	logTypeToBuffer, ok := bs.set[hour]
	if !ok {
		logTypeToBuffer = make(map[string]*s3EventBuffer)
		bs.set[hour] = logTypeToBuffer
	}

	logType := event.PantherLogType
	buffer, ok := logTypeToBuffer[logType]
	if !ok {
		buffer = newS3EventBuffer(logType, hour)
		logTypeToBuffer[logType] = buffer
	}

	return buffer
}

func (bs *s3EventBufferSet) removeBuffer(buffer *s3EventBuffer) {
	logTypeToBuffer, ok := bs.set[buffer.hour]
	if !ok {
		return
	}
	bs.totalBufferedMemBytes -= (uint64)(buffer.bytes)
	delete(logTypeToBuffer, buffer.logType)
	if len(logTypeToBuffer) == 0 {
		delete(bs.set, buffer.hour)
	}
}

func (bs *s3EventBufferSet) largestBuffer() (largestBuffer *s3EventBuffer) {
	var maxBufferSize int
	_ = bs.apply(func(buffer *s3EventBuffer) (bool, error) { // we do not return any errors
		if buffer.bytes > maxBufferSize {
			maxBufferSize = buffer.bytes
			largestBuffer = buffer
		}
		return false, nil
	})
	return largestBuffer
}

func (bs *s3EventBufferSet) apply(f func(buffer *s3EventBuffer) (bool, error)) error {
	for _, logTypeToBuffer := range bs.set {
		for _, buffer := range logTypeToBuffer {
			stop, err := f(buffer)
			if err != nil || stop {
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
func (b *s3EventBuffer) addEvent(data []byte) (int, error) {
	// FIXME: To have proper JSONL data in the buffers we need to write "\n" *before* writing the JSON if startBufferSize is zero
	startBufferSize := b.buffer.Len()
	if _, err := b.writer.Write(data); err != nil {
		return 0, err
	}
	if _, err := b.writer.Write(newLineDelimiter); err != nil {
		return 0, errors.Wrap(err, "failed to add data to buffer %s")
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
