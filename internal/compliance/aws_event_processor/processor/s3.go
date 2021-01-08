package processor

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyS3(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html
	bucketName := detail.Get("requestParameters.bucketName").Str
	if bucketName == "" {
		zap.L().Error("s3: empty bucket name", zap.String("eventName", metadata.eventName))
		return nil
	}

	s3ARN := arn.ARN{
		Partition: "aws",
		Service:   "s3",
		Region:    "",
		AccountID: "",
		Resource:  bucketName,
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteBucket",
		EventName:    metadata.eventName,
		// Format: arn:aws:s3:::bucket_name
		ResourceID:   s3ARN.String(),
		ResourceType: schemas.S3BucketSchema,
	}}
}
