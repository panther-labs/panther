package s3batch

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

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"
)

// AWS limit: each DeleteObjects request can specify up to 1000 keys.
const maxObjects = 1000

type deleteObjectsRequest struct {
	client  s3iface.S3API
	input   *s3.DeleteObjectsInput
	deleted int // Records deleted successfully across all requests
}

// send is a wrapper around s3.DeleteObjects which satisfies backoff.Operation.
func (r *deleteObjectsRequest) send() error {
	zap.L().Debug("invoking s3.DeleteObjects", zap.Int("records", len(r.input.Delete.Objects)))
	response, err := r.client.DeleteObjects(r.input)
	if err != nil {
		return &backoff.PermanentError{Err: err}
	}

	r.deleted += len(response.Deleted)

	// Some subset of the records failed - retry only the failed ones.
	if len(response.Errors) > 0 {
		err = fmt.Errorf("%d unprocessed items", len(response.Errors))
		zap.L().Warn("backoff: batch delete objects failed", zap.Error(err))

		retryObjects := make([]*s3.ObjectIdentifier, len(response.Errors))
		for i, result := range response.Errors {
			zap.L().Warn(
				"delete failure",
				zap.String("code", *result.Code),
				zap.String("message", *result.Message),
			)
			retryObjects[i] = &s3.ObjectIdentifier{Key: result.Key, VersionId: result.VersionId}
		}
		r.input.Delete.Objects = retryObjects
		return err
	}

	return nil
}

// DeleteObjects removes object versions from S3 with paging, backoff, and auto-retry.
func DeleteObjects(
	client s3iface.S3API,
	maxElapsedTime time.Duration,
	input *s3.DeleteObjectsInput,
) error {

	zap.L().Info(
		"starting s3batch.DeleteObjects", zap.Int("totalObjects", len(input.Delete.Objects)))
	start := time.Now()

	config := backoff.NewExponentialBackOff()
	config.MaxElapsedTime = maxElapsedTime
	allObjects := input.Delete.Objects
	request := &deleteObjectsRequest{client: client, input: input}

	// Break records into multiple requests as necessary
	for i := 0; i < len(allObjects); i += maxObjects {
		if i+maxObjects >= len(allObjects) {
			input.Delete.Objects = allObjects[i:] // Last batch - whatever is left
		} else {
			input.Delete.Objects = allObjects[i : i+maxObjects]
		}

		if err := backoff.Retry(request.send, config); err != nil {
			zap.L().Error(
				"DeleteObjects permanently failed",
				zap.Int("deletedObjects", request.deleted),
				zap.Int("failedCount", len(allObjects)-request.deleted),
				zap.Error(err),
			)
			return err
		}
	}

	zap.L().Info("DeleteObjects successful", zap.Duration("duration", time.Since(start)))
	return nil
}
