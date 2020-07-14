package firehosebatch

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
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/firehose/firehoseiface"
	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
)

// Will call PutRecordBatch, retrying individual record failures.
// TODO  This method doesn't currently handle  requests greater than 4MB or 500 records
func Send(ctx context.Context, client firehoseiface.FirehoseAPI, input firehose.PutRecordBatchInput, maxRetries int) error {
	batchRequest := &request{
		ctx:              ctx,
		client:           client,
		streamName:       input.DeliveryStreamName,
		remainingRecords: input.Records,
	}
	operationBackoff := backoff.WithContext(
		backoff.WithMaxRetries(
			backoff.NewExponentialBackOff(), uint64(maxRetries)),
		ctx)
	if err := backoff.Retry(batchRequest.send, operationBackoff); err != nil {
		return errors.Wrap(err, "failed to send PutRecordBatch")
	}
	return nil
}

type request struct {
	ctx              context.Context
	client           firehoseiface.FirehoseAPI
	streamName       *string
	remainingRecords []*firehose.Record
}

func (r *request) send() error {
	request := &firehose.PutRecordBatchInput{
		DeliveryStreamName: r.streamName,
		Records:            r.remainingRecords,
	}
	response, err := r.client.PutRecordBatchWithContext(r.ctx, request)
	if err != nil {
		return err
	}
	if aws.Int64Value(response.FailedPutCount) == 0 {
		return nil
	}

	var recordsToRetry []*firehose.Record
	for i, record := range response.RequestResponses {
		if record.ErrorCode != nil {
			recordsToRetry = append(recordsToRetry, request.Records[i])
		}
	}
	r.remainingRecords = recordsToRetry
	return errors.Errorf("failed to send %d events", len(recordsToRetry))
}
