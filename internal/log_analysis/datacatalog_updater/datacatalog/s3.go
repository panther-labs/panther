package datacatalog

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

	"github.com/aws/aws-lambda-go/events"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

func (h *LambdaHandler) HandleS3Event(ctx context.Context, event *events.S3Event) (err error) {
	logger := lambdalogger.FromContext(ctx)
	if len(event.Records) == 0 { // indications of a bug someplace
		logger.Warn("no s3 event notifications in message", zap.Any("message", &event))
		return
	}
	for i := range event.Records {
		s3Event := &event.Records[i]
		if e := h.HandleS3EventRecord(ctx, s3Event); e != nil {
			err = multierr.Append(err, e)
		}
	}
	return
}

func (h *LambdaHandler) HandleS3EventRecord(ctx context.Context, event *events.S3EventRecord) error {
	bucketName := event.S3.Bucket.Name
	objectKey := event.S3.Object.Key
	partition, err := awsglue.PartitionFromS3Object(bucketName, objectKey)
	if err != nil {
		lambdalogger.FromContext(ctx).Warn("invalid S3 event", zap.Any("event", event))
		return nil
	}
	partitionURL := partition.PartitionLocation()
	if h.isPartitionAlreadyCreated(partitionURL) {
		return nil
	}
	partitionTime := partition.GetTime()
	tableMeta := partition.GetGlueTableMetadata()
	if _, err := tableMeta.CreateJSONPartition(h.GlueClient, partitionTime); err != nil {
		return errors.Wrapf(err, "cannot create partition for s3://%s/%s", bucketName, objectKey)
	}

	h.observeCreatedPartition(partitionURL)

	return nil
}

func (h *LambdaHandler) isPartitionAlreadyCreated(partitionURL string) bool {
	_, created := h.partitionsCreated[partitionURL]
	return created
}

func (h *LambdaHandler) observeCreatedPartition(partitionURL string) {
	// Store partition in cache as successfully created
	if h.partitionsCreated == nil {
		h.partitionsCreated = make(map[string]struct{})
	}
	h.partitionsCreated[partitionURL] = struct{}{}
}
