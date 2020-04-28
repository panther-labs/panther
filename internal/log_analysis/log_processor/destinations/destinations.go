package destinations

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
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sns"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// Destination defines the interface that all Destinations should follow
type Destination interface {
	SendEvents(parsedEventChannel chan *parsers.PantherLog, errChan chan error)
}

// CreateDestination the method returns the appropriate Destination based on configuration
func CreateDestination() Destination {
	zap.L().Debug("creating S3 destination")
	s3BucketName := os.Getenv("S3_BUCKET")

	if s3BucketName != "" {
		return createS3Destination(s3BucketName)
	}
	return createFirehoseDestination()
}

func createFirehoseDestination() Destination {
	client := firehose.New(common.Session)
	zap.L().Debug("created Firehose destination")
	return &FirehoseDestination{
		client:         client,
		firehosePrefix: "panther",
	}
}

func createS3Destination(s3BucketName string) Destination {
	// do not need to check error below, maxS3BufferMemUsageBytes() will panic if not set
	lambdaSize, _ := strconv.Atoi(os.Getenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE"))
	return &S3Destination{
		s3Uploader:          s3manager.NewUploader(common.Session),
		snsClient:           sns.New(common.Session),
		s3Bucket:            s3BucketName,
		snsTopicArn:         os.Getenv("SNS_TOPIC_ARN"),
		maxBufferedMemBytes: maxS3BufferMemUsageBytes(lambdaSize),
		maxDuration:         maxDuration,
	}
}
