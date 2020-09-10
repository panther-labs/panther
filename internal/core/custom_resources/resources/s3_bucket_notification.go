package resources

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
	"fmt"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
)

type S3BucketNotificationProperties = s3.PutBucketNotificationConfigurationInput

func customS3BucketNotification(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props S3BucketNotificationProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		// CF only natively allows defining bucket notifications at the time of bucket creation.
		if _, err := s3Client.PutBucketNotificationConfiguration(&props); err != nil {
			return "", nil, err
		}

		return fmt.Sprintf("custom:s3bucketnotification:%s", *props.Bucket), nil, nil

	case cfn.RequestDelete:
		split := strings.Split(event.PhysicalResourceID, ":")
		if len(split) < 3 {
			// Invalid physicalID (e.g. CREATE_FAILED), skip delete
			return event.PhysicalResourceID, nil, nil
		}

		bucketName := split[len(split)-1]

		// You have to put an empty notification configuration to remove it
		_, err := s3Client.PutBucketNotificationConfiguration(&s3.PutBucketNotificationConfigurationInput{
			Bucket:                    &bucketName,
			NotificationConfiguration: &s3.NotificationConfiguration{},
		})
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == s3.ErrCodeNoSuchBucket {
			err = nil // bucket already deleted
		}

		return event.PhysicalResourceID, nil, err

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}
