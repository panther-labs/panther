package process

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
	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

var (
	// partitionPrefixCache is a cache that stores all the prefixes of the partitions we have created
	// The cache is used to avoid attempts to create the same partitions in Glue table
	partitionPrefixCache = make(map[string]struct{})
)

func SQS(event events.SQSEvent) error {
	for _, record := range event.Records {
		// uncomment to see all payloads
		//zap.L().Debug("processing record", zap.String("content", record.Body))
		notification := &models.S3Notification{}
		if err := jsoniter.UnmarshalFromString(record.Body, notification); err != nil {
			zap.L().Error("failed to unmarshal record", zap.Error(errors.WithStack(err)))
			continue
		}

		if len(notification.Records) == 0 { // indications of a bug someplace
			zap.L().Warn("no s3 event notifications in message", zap.String("message", record.Body))
			continue
		}

		for _, eventRecord := range notification.Records {
			existsInCache, gluePartition, err := getPartition(eventRecord.S3.Bucket.Name, eventRecord.S3.Object.Key)
			if err != nil {
				zap.L().Error("failed to get partition information from notification",
					zap.Any("notification", notification), zap.Error(err))
				continue
			}
			if existsInCache { // already exists, nothing to do
				continue
			}

			// attempt to create the partition
			_, err = gluePartition.GetGlueTableMetadata().CreateJSONPartition(glueClient, gluePartition.GetTime())
			if err != nil {
				return errors.Wrapf(err, "failed to create partition %#v", notification)
			}

			// remember in cache
			partitionPrefixCache[gluePartition.GetPartitionLocation()] = struct{}{}
		}
	}
	return nil
}

func getPartition(bucketName, key string) (existsInCache bool, gluePartition *awsglue.GluePartition, err error) {
	gluePartition, err = awsglue.GetPartitionFromS3(bucketName, key)
	if err != nil {
		return false, nil, errors.Wrapf(err, "cannot get partition from s3://%s/%s", bucketName, key)
	}

	// already done?
	partitionLocation := gluePartition.GetPartitionLocation()
	if _, ok := partitionPrefixCache[partitionLocation]; ok {
		zap.L().Debug("partition has already been created")
		return true, gluePartition, nil
	}

	return false, gluePartition, nil
}
