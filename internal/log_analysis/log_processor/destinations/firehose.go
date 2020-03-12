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
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/firehose/firehoseiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	maxRecordNumber = 500             // 500 records maximum in a batch request
	maxRequestBytes = 4 * 1000 * 1000 // 4MB max request size
)

// FirehoseDestination sends classified events to Kinesis Firehose
type FirehoseDestination struct {
	client         firehoseiface.FirehoseAPI
	firehosePrefix string
}

// SendEvents sends events to Kinesis firehose streams
// It continuously reads events from outputChannel, groups them in batches per log type
// and sends them to the appropriate Kinesis FIrehose. If the method encounters an error
// it stops reading from the outputChannel and writes an error to the errorChannel
func (destination *FirehoseDestination) SendEvents(parsedEventChannel chan *parsers.PantherLog, errChan chan error) {
	logtypeToRecords := make(map[string]*recordBatch)
	eventsProcessed := 0
	zap.L().Info("starting to read events from channel")
	for event := range parsedEventChannel {
		eventsProcessed++
		data, err := jsoniter.Marshal(event.Event)
		if err != nil {
			zap.L().Warn("failed to marshall event", zap.Error(err))
			errChan <- err
			continue
		}
		currentRecord := &firehose.Record{
			Data: data,
		}

		logType := *event.PantherLogType
		records, ok := logtypeToRecords[logType]
		if !ok {
			records = &recordBatch{}
			logtypeToRecords[logType] = records
		}

		if !records.addRecord(currentRecord) {
			err := destination.sendRecords(logType, records.records)
			if err != nil {
				zap.L().Warn("failed to send records to firehose", zap.Error(err))
				errChan <- err
				continue
			}
			records.initialize(currentRecord)
		}
	}

	zap.L().Info("output channel closed, sending last events")
	// If the channel has been closed
	// send the buffered messages before terminating
	for logType, info := range logtypeToRecords {
		err := destination.sendRecords(logType, info.records)
		if err != nil {
			zap.L().Warn("failed to send records to firehose", zap.Error(err))
			errChan <- err
			continue
		}
	}
	zap.L().Info("Finished sending messages", zap.Int("events", eventsProcessed))
}

func (destination *FirehoseDestination) sendRecords(logType string, records []*firehose.Record) error {
	batchMessage := &firehose.PutRecordBatchInput{
		Records:            records,
		DeliveryStreamName: destination.getStreamName(logType),
	}
	zap.L().Debug("sending batch to firehose",
		zap.Int("records", len(records)),
		zap.String("logType", logType),
		zap.String("streamName", *batchMessage.DeliveryStreamName))

	output, err := destination.client.PutRecordBatch(batchMessage)

	if err != nil {
		zap.L().Warn("failed to send records to firehose",
			zap.String("streamName", *batchMessage.DeliveryStreamName),
			zap.Error(err))
		return err
	}

	if aws.Int64Value(output.FailedPutCount) > 0 {
		zap.L().Warn("failed to send records to firehose",
			zap.String("streamName", *batchMessage.DeliveryStreamName),
			zap.Int64("failedRecords", *output.FailedPutCount))
		return errors.New("failed to send records to firehose")
	}
	return nil
}

func (destination *FirehoseDestination) getStreamName(logType string) *string {
	// converting "AWS.CloudTrail" to "panther_data_aws_cloudtrail"
	formattedType := strings.Replace(strings.ToLower(logType), ".", "_", -1)
	return aws.String(destination.firehosePrefix + "_" + formattedType)
}

// recordBatch represents a batch of Kinesis Firehose records
type recordBatch struct {
	records      []*firehose.Record
	requestBytes int
}

// addRecord adds a Record to the recordBatch
// If it returns true, the record was added successfully.
// If it returns false, the record couldn't be added because the batch has exceeded
// Firehose Batch API limits
func (r *recordBatch) addRecord(record *firehose.Record) bool {
	// The number of records in the batch if the record is added
	projectedRecordNumber := len(r.records) + 1

	// The size of the batch in bytes if the record is added
	projectedRequestBytes := r.requestBytes + len(record.Data)

	if projectedRecordNumber > maxRecordNumber || projectedRequestBytes > maxRequestBytes {
		return false
	}

	r.requestBytes = projectedRequestBytes
	r.records = append(r.records, record)
	return true
}

// initialize configures recordBatch with a Firehose Record
func (r *recordBatch) initialize(record *firehose.Record) {
	r.requestBytes = len(record.Data)
	r.records = []*firehose.Record{record}
}
