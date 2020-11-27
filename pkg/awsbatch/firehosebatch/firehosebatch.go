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

const (
	// Limitations on firehose per AWS docs https://docs.aws.amazon.com/firehose/latest/dev/limits.html
	// "The PutRecordBatch operation can take up to 500 records per call or 4 MiB per call, whichever is smaller."
	maxMessages = 500
	// Strictly speaking, the max should be around 4194300 bytes, but we come in a bit below that to
	// avoid any finnicky-ness in header size etc.
	maxBytes = 4190000
)

// BatchSend will break the input up into smaller requests based on the firehose size constraints,
// then call Send to forward those batches. Returns an error for non-retryable errors, and returns a
// list of records that are too big to send so the caller can handle those records as desired.
func BatchSend(ctx context.Context,
	client firehoseiface.FirehoseAPI,
	input firehose.PutRecordBatchInput,
	maxRetries int) ([]*firehose.Record, error) {

	var err error
	bigMessages := make([]*firehose.Record, 0)
	for i := 0; i < len(input.Records); {
		var messages, bytes int
		// Count up how many messages we can send in the next batch
		for _, record := range input.Records[i:] {
			if messages+1 > maxMessages || bytes+len(record.Data) > maxBytes {
				break
			}
			messages++
			bytes += len(record.Data)
		}

		// If a single record was too big to send, record it & keep going
		if messages == 0 {
			bigMessages = append(bigMessages, input.Records[i])
			i++
			continue
		}

		batchInput := firehose.PutRecordBatchInput{
			DeliveryStreamName: input.DeliveryStreamName,
			Records:            input.Records[i : i+messages],
		}
		// TODO: we could likely parallelize this Send so larger lambdas can work more efficiently
		err = Send(ctx, client, batchInput, maxRetries)
		if err != nil {
			break
		}
		i += messages
	}
	return bigMessages, err
}

// Send will call PutRecordBatch, retrying individual record failures.
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
