package notify

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

import "github.com/aws/aws-lambda-go/events"

// S3Notification is sent when new data is available in S3
type S3Notification struct {
	// https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
	Records []events.S3EventRecord
}

func NewS3ObjectPutNotification(bucket, key string, nbytes int) *S3Notification {
	const (
		eventVersion = "2.0"
		eventSource  = "aws:s3"
		eventName    = "ObjectCreated:Put"
	)
	return &S3Notification{
		Records: []events.S3EventRecord{
			{
				EventVersion: eventVersion,
				EventSource:  eventSource,
				EventName:    eventName,
				S3: events.S3Entity{
					Bucket: events.S3Bucket{
						Name: bucket,
					},
					Object: events.S3Object{
						Key:  key,
						Size: int64(nbytes), // this is very important to include because some subscribers will ignore 0 length files
					},
				},
			},
		},
	}
}
