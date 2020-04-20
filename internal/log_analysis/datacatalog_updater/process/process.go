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
	"github.com/panther-labs/panther/pkg/awsglue"
)

var (
	// partitionPrefixCache is a cache that stores all the prefixes of the partitions we have created
	// The cache is used to avoid attempts to create the same partitions in Glue table
	partitionPrefixCache = make(map[string]struct{})
)

func SQS(event events.SQSEvent) error {
	for _, record := range event.Records {
		zap.L().Debug("processing record", zap.String("content", record.Body))
		notification := &models.S3Notification{}
		if err := jsoniter.UnmarshalFromString(record.Body, notification); err != nil {
			zap.L().Error("failed to unmarshal record", zap.Error(errors.WithStack(err)))
			continue
		}

		if len(notification.Records) == 0 { // indications of a bug someplace
			zap.L().Warn("no s3 event notifications in message",
				zap.String("message", record.Body))
			continue
		}

		for _, eventRecord := range notification.Records {
			gluePartition, err := awsglue.GetPartitionFromS3(eventRecord.S3.Bucket.Name, eventRecord.S3.Object.Key)
			if err != nil {
				zap.L().Error("failed to get partition information from notification",
					zap.Any("notification", notification), zap.Error(errors.WithStack(err)))
				continue
			}

			// already done?
			partitionLocation := gluePartition.GetPartitionLocation()
			if _, ok := partitionPrefixCache[partitionLocation]; ok {
				zap.L().Debug("partition has already been created")
				continue
			}

			created, err := gluePartition.CreatePartition(glueClient)
			if err != nil {
				err = errors.Wrapf(err, "failed to create partition: %#v", notification)
				return err
			}
			partitionPrefixCache[partitionLocation] = struct{}{} // remember

			if created { // schedule conversion to Parquet
				input := &GenerateParquetInput{
					DatabaseName:         gluePartition.GetDatabase(),
					TableName:            gluePartition.GetTable(),
					HistoricalBucketName: envConfig.HistoricalDataBucket,
					PartitionHour:        gluePartition.GetHour(),
				}
				_, err = GenerateParquet(input)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
