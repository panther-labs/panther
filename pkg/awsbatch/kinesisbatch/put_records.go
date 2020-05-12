package kinesisbatch

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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/aws/aws-sdk-go/service/kinesis/kinesisiface"
	"github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

// AWS limit: each PutRecords request can support up to 500 records.
const maxRecords = 500

type putRecordsRequest struct {
	client       kinesisiface.KinesisAPI
	input        *kinesis.PutRecordsInput
	successCount int // Total number of records that have sent successfully across all requests
}

// send is a wrapper around kinesis.PutRecords which satisfies backoff.Operation.
func (r *putRecordsRequest) send() error {
	zap.L().Debug("invoking kinesis.PutRecords", zap.Int("records", len(r.input.Records)))
	response, err := r.client.PutRecords(r.input)

	if err != nil {
		// This was a service error - it can sometimes be retried
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == kinesis.ErrCodeProvisionedThroughputExceededException {
				zap.L().Warn("backoff: stream throughput exceeded", zap.Error(awsErr))
				return awsErr
			}
		}
		return &backoff.PermanentError{Err: err}
	}

	r.successCount += len(r.input.Records)

	// Some subset of the records failed - retry only the failed ones
	if response.FailedRecordCount != nil && *response.FailedRecordCount > 0 {
		r.successCount -= int(*response.FailedRecordCount)
		err = fmt.Errorf("%d failed records", int(*response.FailedRecordCount))
		zap.L().Warn("backoff: batch put records failed", zap.Error(err))

		var retryRecords []*kinesis.PutRecordsRequestEntry
		for i, result := range response.Records {
			if result.ErrorMessage != nil {
				zap.L().Warn("record failure", zap.String("error", *result.ErrorMessage))
				retryRecords = append(retryRecords, r.input.Records[i])
			}
		}
		r.input.Records = retryRecords
		return err
	}

	return nil
}

// PutRecords puts records to Kinesis with paging, backoff, and auto-retry for failed items.
func PutRecords(
	client kinesisiface.KinesisAPI, maxElapsedTime time.Duration, input *kinesis.PutRecordsInput) error {

	zap.L().Info("starting kinesisbatch.PutRecords", zap.Int("totalRecords", len(input.Records)))
	start := time.Now()

	config := backoff.NewExponentialBackOff()
	config.MaxElapsedTime = maxElapsedTime
	allRecords := input.Records
	request := &putRecordsRequest{client: client, input: input}

	// Break records into multiple requests as necessary
	for i := 0; i < len(allRecords); i += maxRecords {
		if i+maxRecords >= len(allRecords) {
			input.Records = allRecords[i:] // Last batch - whatever is left
		} else {
			input.Records = allRecords[i : i+maxRecords]
		}

		if err := backoff.Retry(request.send, config); err != nil {
			zap.L().Error(
				"PutRecords permanently failed",
				zap.Int("sentRecordCount", request.successCount),
				zap.Int("failedRecordCount", len(allRecords)-request.successCount),
				zap.Error(err),
			)
			return err
		}
	}

	zap.L().Info("PutRecords successful", zap.Duration("duration", time.Since(start)))
	return nil
}
