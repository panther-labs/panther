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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
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

	maxFileSize = 100 * 1000 * 1000 // 100MB uncompressed file size, should result in ~10MB output file size
	// it should always be greater than the maximum expected event (log line) size

	maxDuration = 1 * time.Minute //hHolding events for maximum 1 minute in memory
)

var (
	newLineDelimiter = []byte("\n")

	parserRegistry registry.Interface = registry.AvailableParsers() // initialize
)

// S3Destination sends normalized events to S3
type S3Destination struct {
	s3Client  s3iface.S3API
	snsClient snsiface.SNSAPI
	// s3Bucket is the s3Bucket where the data will be stored
	s3Bucket string
	// snsTopic is the SNS Topic ARN where we will send the notification
	// when we store new data in S3
	snsTopicArn string
	// thresholds for ejection
	maxFileSize int
	maxDuration time.Duration
}

// SendEvents stores events in S3.
// It continuously reads events from outputChannel, groups them in batches per log type
// and stores them in the appropriate S3 path. If the method encounters an error
// it writes an error to the errorChannel and continues until channel is closed (skipping events).
func (destination *S3Destination) SendEvents(parsedEventChannel chan *parsers.PantherLog, errChan chan error) {
	// used to flush expired buffers
	flushExpired := time.NewTicker(destination.maxDuration)
	defer flushExpired.Stop()

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
		case expireTime := <-flushExpired.C:
			err := bufferSet.apply(func(b *s3EventBuffer) error {
				if expireTime.Sub(b.createTime) >= destination.maxDuration {
					if sendErr := destination.sendData(b); sendErr != nil {
						return sendErr
					}
				}
				return nil
			})
			if err != nil {
				failed = true
				errChan <- err
				continue
			}
		default: // makes select non-blocking
		}

		data, err := jsoniter.Marshal(event.Event())
		if err != nil {
			failed = true
			errChan <- errors.Wrap(err, "failed to marshall log parser event for S3")
			continue
		}

		buffer := bufferSet.getBuffer(event)

		err = buffer.addEvent(data)
		if err != nil {
			failed = true
			errChan <- err
			continue
		}

		// Check if buffer is bigger than threshold
		if buffer.bytes >= destination.maxFileSize {
			if err = destination.sendData(buffer); err != nil {
				failed = true
				errChan <- err
				continue
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
		if err := destination.sendData(buffer); err != nil {
			errChan <- err
		}
		return nil
	})

	zap.L().Debug("finished sending messages", zap.Int("events", eventsProcessed))
}

// sendData puts data in S3 and sends notification to SNS
func (destination *S3Destination) sendData(buffer *s3EventBuffer) (err error) {
	if buffer.events == 0 { // skip empty buffers
		return nil
	}
	var contentLength int64 = 0

	key := getS3ObjectKey(buffer.logType, buffer.hour)

	operation := common.OpLogManager.Start("sendData", common.OpLogS3ServiceDim)
	defer func() {
		if resetErr := buffer.reset(); resetErr != nil {
			operation.LogError(resetErr)
		}
		operation.Stop()
		operation.Log(err,
			// s3 dim info
			zap.Int64("contentLength", contentLength),
			zap.String("bucket", destination.s3Bucket),
			zap.String("key", key))
	}()

	payload, err := buffer.read()
	if err != nil {
		return err
	}

	contentLength = int64(len(payload)) // for logging

	request := &s3.PutObjectInput{
		Bucket: aws.String(destination.s3Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(payload),
	}
	if _, err = destination.s3Client.PutObject(request); err != nil {
		err = errors.Wrap(err, "PutObject")
		return err
	}

	err = destination.sendSNSNotification(key, buffer) // if send fails we fail whole operation

	return err
}

func (destination *S3Destination) sendSNSNotification(key string, buffer *s3EventBuffer) error {
	var err error
	operation := common.OpLogManager.Start("sendSNSNotification", common.OpLogSNSServiceDim)
	defer func() {
		operation.Stop()
		operation.Log(err,
			zap.String("topicArn", destination.snsTopicArn))
	}()

	s3Notification := &models.S3Notification{
		S3Bucket:    aws.String(destination.s3Bucket),
		S3ObjectKey: aws.String(key),
		Events:      aws.Int(buffer.events),
		Bytes:       aws.Int(buffer.bytes),
		Type:        aws.String(models.LogData.String()),
		ID:          aws.String(buffer.logType),
	}

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

func getS3ObjectKey(logType string, timestamp time.Time) string {
	return fmt.Sprintf(s3ObjectKeyFormat,
		parserRegistry.LookupParser(logType).GlueTableMetadata.GetPartitionPrefix(timestamp.UTC()), // get the path to store the data in S3
		timestamp.Format(S3ObjectTimestampFormat),
		uuid.New().String())
}

// s3BufferSet is a group of buffers associated with hour time bins, pointing to maps logtype->s3EventBuffer
type s3EventBufferSet map[time.Time]map[string]*s3EventBuffer

func newS3EventBufferSet() s3EventBufferSet {
	return make(map[time.Time]map[string]*s3EventBuffer)
}

func (bs s3EventBufferSet) getBuffer(event *parsers.PantherLog) *s3EventBuffer {
	// bin by hour (this is our partition size)
	hour := (time.Time)(*event.PantherEventTime).Truncate(time.Hour)

	logTypeToBuffer, ok := bs[hour]
	if !ok {
		logTypeToBuffer = make(map[string]*s3EventBuffer)
		bs[hour] = logTypeToBuffer
	}

	logType := *event.PantherLogType
	buffer, ok := logTypeToBuffer[logType]
	if !ok {
		buffer = newS3EventBuffer(logType, hour)
		_ = buffer.reset() // no need to check error
		logTypeToBuffer[logType] = buffer
	}

	return buffer
}

func (bs s3EventBufferSet) apply(f func(buffer *s3EventBuffer) error) error {
	for _, logTypeToBuffer := range bs {
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
	return &s3EventBuffer{
		logType:    logType,
		hour:       hour,
		createTime: time.Now(), // used with time.After() to check expiration ... no need for UTC()
	}
}

// addEvent adds new data to the s3EventBuffer
func (b *s3EventBuffer) addEvent(event []byte) error {
	var nbytes int

	bytesWritten, err := b.writer.Write(event)
	if err != nil {
		err = errors.Wrap(err, "failed to add data to buffer %s")
		return err
	}
	nbytes += bytesWritten

	// Adding new line delimiter
	bytesWritten, err = b.writer.Write(newLineDelimiter)
	if err != nil {
		err = errors.Wrap(err, "failed to add data to buffer")
		return err
	}
	nbytes += bytesWritten

	b.bytes += nbytes
	b.events++
	return nil
}

func (b *s3EventBuffer) read() ([]byte, error) {
	if b.writer != nil {
		if err := b.writer.Close(); err != nil {
			return nil, errors.Wrap(err, "close failed in buffer read()")
		}
	}
	return b.buffer.Bytes(), nil
}

// reset resets the s3EventBuffer
func (b *s3EventBuffer) reset() error {
	b.bytes = 0
	b.events = 0
	if b.writer != nil {
		if err := b.writer.Close(); err != nil {
			return errors.Wrap(err, "close failed in buffer reset()")
		}
	}
	b.buffer = &bytes.Buffer{}
	b.writer = gzip.NewWriter(b.buffer)
	return nil
}
