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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

// s3ObjectKeyFormat represents the format of the S3 object key
const s3ObjectKeyFormat = "%s%s-%s.gz"

var (
	maxFileSize = 100 * 1000 * 1000 // 100MB uncompressed file size, should result in ~10MB output file size
	// It should always be greater than the maximum expected event (log line) size
	maxDuration      = 1 * time.Minute // Holding events for maximum 1 minute in memory
	newLineDelimiter = []byte("\n")

	parserRegistry registry.Interface = registry.AvailableParsers() // initialize
)

// S3Destination sends normalized events to S3
type S3Destination struct {
	s3Client   s3iface.S3API
	snsClient  snsiface.SNSAPI
	glueClient glueiface.GlueAPI
	// s3Bucket is the s3Bucket where the data will be stored
	s3Bucket string
	// snsTopic is the SNS Topic ARN where we will send the notification
	// when we store new data in S3
	snsTopicArn string
	// used to track existing glue partitions, avoids excessive Glue API calls
	partitionExistsCache map[string]struct{}
}

// SendEvents stores events in S3.
// It continuously reads events from outputChannel, groups them in batches per log type
// and stores them in the appropriate S3 path. If the method encounters an error
// it writes an error to the errorChannel and continues until channel is closed (skipping events).
func (destination *S3Destination) SendEvents(parsedEventChannel chan *common.ParsedEvent, errChan chan error) {
	failed := false // set to true on error and loop will drain channel
	logTypeToBuffer := make(map[string]*s3EventBuffer)
	eventsProcessed := 0
	zap.L().Debug("starting to read events from channel")
	for event := range parsedEventChannel {
		if failed { // drain channel
			continue
		}

		eventsProcessed++
		data, err := jsoniter.Marshal(event.Event)
		if err != nil {
			failed = true
			errChan <- errors.Wrap(err, "failed to marshall log parser event for S3")
			continue
		}

		buffer, ok := logTypeToBuffer[event.LogType]
		if !ok {
			buffer = &s3EventBuffer{}
			logTypeToBuffer[event.LogType] = buffer
		}

		canAdd, err := buffer.addEvent(data)
		if err != nil {
			failed = true
			errChan <- err
			continue
		}
		if !canAdd {
			if err = destination.sendData(event.LogType, buffer); err != nil {
				failed = true
				errChan <- err
				continue
			}

			canAdd, err = buffer.addEvent(data)
			if err != nil {
				failed = true
				errChan <- err
				continue
			}
			if !canAdd {
				failed = true
				// happens if a single marshalled event is greater than maxFileSize, something that shouldn't happen normally
				errChan <- errors.WithMessagef(err, "event doesn't fit in single s3 object, cannot write to %s",
					destination.s3Bucket)
				continue
			}
		}

		// Check if any buffers has data for longer than 1 minute
		if err = destination.sendExpiredData(logTypeToBuffer); err != nil {
			failed = true
			errChan <- err
			continue
		}
	}

	if failed {
		zap.L().Debug("failed, returning after draining parsedEventsChannel")
	}

	zap.L().Debug("output channel closed, sending last events")
	// If the channel has been closed
	// send the buffered messages before terminating
	for logType, data := range logTypeToBuffer {
		if err := destination.sendData(logType, data); err != nil {
			errChan <- err
			return
		}
	}
	zap.L().Debug("finished sending messages", zap.Int("events", eventsProcessed))
}

func (destination *S3Destination) sendExpiredData(logTypeToEvents map[string]*s3EventBuffer) error {
	currentTime := time.Now().UTC()
	for logType, buffer := range logTypeToEvents {
		if currentTime.Sub(buffer.firstEventProcessedTime) > maxDuration {
			err := destination.sendData(logType, buffer)
			if err != nil {
				return err
			}
			// delete the entry after sending the data
			delete(logTypeToEvents, logType)
		}
	}
	return nil
}

// sendData puts data in S3 and sends notification to SNS
func (destination *S3Destination) sendData(logType string, buffer *s3EventBuffer) (err error) {
	var contentLength int64 = 0

	key := getS3ObjectKey(logType, buffer.firstEventProcessedTime)

	operation := common.OpLogManager.Start("sendData", common.OpLogS3ServiceDim)
	defer func() {
		// if no error reset buffer
		if err == nil {
			if err = buffer.reset(); err != nil {
				err = errors.Wrap(err, "failed to reset buffer")
			}
		}

		operation.Stop()
		operation.Log(err,
			// s3 dim info
			zap.Int64("contentLength", contentLength),
			zap.String("bucket", destination.s3Bucket),
			zap.String("key", key))
	}()

	payload, err := buffer.getBytes()
	if err != nil {
		err = errors.Wrap(err, "failed to read buffer")
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

	destination.createGluePartition(logType, buffer) // best effort

	err = destination.sendSNSNotification(key, logType, buffer) // if send fails we fail whole operation

	return err
}

func (destination *S3Destination) sendSNSNotification(key, logType string, buffer *s3EventBuffer) error {
	var err error
	operation := common.OpLogManager.Start("sendSNSNotification", common.OpLogSNSServiceDim)
	defer func() {
		operation.Stop()
		operation.Log(err,
			zap.String("topicArn", destination.snsTopicArn))
	}()

	s3Notification := &common.S3Notification{
		S3Bucket:    aws.String(destination.s3Bucket),
		S3ObjectKey: aws.String(key),
		Events:      aws.Int(buffer.events),
		Bytes:       aws.Int(buffer.bytes),
		Type:        aws.String(common.LogData),
		ID:          aws.String(logType),
	}

	marshalledNotification, err := jsoniter.MarshalToString(s3Notification)
	if err != nil {
		err = errors.Wrap(err, "failed to marshal notification")
		return err
	}

	input := &sns.PublishInput{
		TopicArn: aws.String(destination.snsTopicArn),
		Message:  aws.String(marshalledNotification),
	}
	if _, err = destination.snsClient.Publish(input); err != nil {
		err = errors.Wrap(err, "failed to send notification to topic")
		return err
	}

	return err
}

// create glue partition (best effort and log)
func (destination *S3Destination) createGluePartition(logType string, buffer *s3EventBuffer) {
	glueMetadata := parserRegistry.LookupParser(logType).Glue
	partitionPath := glueMetadata.PartitionPrefix(buffer.firstEventProcessedTime)
	if _, exists := destination.partitionExistsCache[partitionPath]; !exists {
		operation := common.OpLogManager.Start("createPartition", common.OpLogGlueServiceDim)
		partitionErr := glueMetadata.CreateJSONPartition(destination.glueClient, buffer.firstEventProcessedTime)
		// already done? fast path return
		if partitionErr != nil {
			if awsErr, ok := partitionErr.(awserr.Error); ok {
				if awsErr.Code() == "AlreadyExistsException" {
					destination.partitionExistsCache[partitionPath] = struct{}{} // remember
					return
				}
			}
		} else {
			destination.partitionExistsCache[partitionPath] = struct{}{} // remember
		}

		// log outcome
		operation.Stop()
		operation.Log(partitionErr,
			zap.String("bucket", destination.s3Bucket),
			zap.String("partition", partitionPath))
	}
}

func getS3ObjectKey(logType string, timestamp time.Time) string {
	return fmt.Sprintf(s3ObjectKeyFormat,
		parserRegistry.LookupParser(logType).Glue.PartitionPrefix(timestamp.UTC()), // get the path used in Glue table
		timestamp.Format("20060102T150405Z"),
		uuid.New().String())
}

// s3EventBuffer is a group of events of the same type
// that will be stored in the same S3 object
type s3EventBuffer struct {
	buffer                  *bytes.Buffer
	writer                  *gzip.Writer
	bytes                   int
	events                  int
	firstEventProcessedTime time.Time
}

// addEvent adds new data to the s3EventBuffer
// If it returns true, the record was added successfully.
// If it returns false, the record couldn't be added because the group has exceeded file size limit
func (b *s3EventBuffer) addEvent(event []byte) (bool, error) {
	if b.buffer == nil {
		b.buffer = &bytes.Buffer{}
		b.writer = gzip.NewWriter(b.buffer)
		b.firstEventProcessedTime = time.Now().UTC()
	}

	// The size of the batch in bytes if the event is added
	projectedFileSize := b.bytes + len(event) + len(newLineDelimiter)
	if projectedFileSize > maxFileSize {
		return false, nil
	}

	_, err := b.writer.Write(event)
	if err != nil {
		err = errors.Wrap(err, "failed to add data to buffer %s")
		return false, err
	}

	// Adding new line delimiter
	_, err = b.writer.Write(newLineDelimiter)
	if err != nil {
		err = errors.Wrap(err, "failed to add data to buffer")
		return false, err
	}
	b.bytes = projectedFileSize
	b.events++
	return true, nil
}

// getBytes returns all bytes in the buffer
func (b *s3EventBuffer) getBytes() ([]byte, error) {
	if err := b.writer.Close(); err != nil {
		return nil, err
	}
	return b.buffer.Bytes(), nil
}

// reset resets the s3EventBuffer
func (b *s3EventBuffer) reset() error {
	b.bytes = 0
	b.events = 0
	if err := b.writer.Close(); err != nil {
		return err
	}
	b.writer = nil
	b.buffer = nil
	return nil
}
