package teardown

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

var log = logger.Build("[teardown]")

const (
	// Upper bound on the number of s3 object versions we'll delete manually.
	s3MaxDeletes = 10000
)

// Delete all objects in panther-* buckets and then remove them.
func DestroyPantherBuckets(client *s3.S3) error {
	response, err := client.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf("failed to list S3 buckets: %v", err)
	}

	for _, bucket := range response.Buckets {
		response, err := client.GetBucketTagging(&s3.GetBucketTaggingInput{Bucket: bucket.Name})
		if err != nil {
			// wrong region, tags do not exist, etc
			continue
		}

		var hasApplicationTag, hasStackTag bool
		for _, tag := range response.TagSet {
			switch aws.StringValue(tag.Key) {
			case "Application":
				hasApplicationTag = aws.StringValue(tag.Value) == "Panther"
			case "Stack":
				hasStackTag = aws.StringValue(tag.Value) == "panther-bootstrap"
			}
		}

		// S3 bucket names are not predictable, and neither are stack names (when using master template).
		// However, both 'mage deploy' and the master template have these tags set.
		if hasApplicationTag && hasStackTag {
			if err := removeBucket(client, bucket.Name); err != nil {
				return err
			}
		}
	}

	return nil
}

// Empty, then delete the given S3 bucket.
//
// Or, if there are too many objects to delete directly, set a 1-day expiration lifecycle policy instead.
func removeBucket(client *s3.S3, bucketName *string) error {
	// Prevent new writes to the bucket
	_, err := client.PutBucketAcl(&s3.PutBucketAclInput{ACL: aws.String("private"), Bucket: bucketName})
	if err != nil {
		if awsutils.IsAnyError(err, s3.ErrCodeNoSuchBucket) {
			log.Debugf("%s already deleted", *bucketName)
			return nil
		}
		return fmt.Errorf("%s put-bucket-acl failed: %v", *bucketName, err)
	}

	input := &s3.ListObjectVersionsInput{Bucket: bucketName}
	var objectVersions []*s3.ObjectIdentifier

	// List all object versions (including delete markers)
	err = client.ListObjectVersionsPages(input, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
		for _, marker := range page.DeleteMarkers {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: marker.Key, VersionId: marker.VersionId})
		}

		for _, version := range page.Versions {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: version.Key, VersionId: version.VersionId})
		}

		// Keep paging as long as we don't have too many items yet
		return len(objectVersions) < s3MaxDeletes
	})
	if err != nil {
		return fmt.Errorf("failed to list object versions for %s: %v", *bucketName, err)
	}

	uri := util.S3URI(*bucketName, "")
	if len(objectVersions) >= s3MaxDeletes {
		log.Warnf("%s has too many items to delete directly, setting an expiration policy instead", uri)
		_, err = client.PutBucketLifecycleConfiguration(&s3.PutBucketLifecycleConfigurationInput{
			Bucket: bucketName,
			LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
				Rules: []*s3.LifecycleRule{
					{
						AbortIncompleteMultipartUpload: &s3.AbortIncompleteMultipartUpload{
							DaysAfterInitiation: aws.Int64(1),
						},
						Expiration: &s3.LifecycleExpiration{
							Days: aws.Int64(1),
						},
						Filter: &s3.LifecycleRuleFilter{
							Prefix: aws.String(""), // empty prefix required to apply rule to all objects
						},
						ID: aws.String("panther-expire-everything"),
						NoncurrentVersionExpiration: &s3.NoncurrentVersionExpiration{
							NoncurrentDays: aws.Int64(1),
						},
						Status: aws.String("Enabled"),
					},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to set expiration policy for %s: %v", *bucketName, err)
		}
		// remove any notifications since we are leaving the bucket (best effort)
		notificationInput := &s3.PutBucketNotificationConfigurationInput{
			Bucket:                    bucketName,
			NotificationConfiguration: &s3.NotificationConfiguration{}, // posting an empty config clears (not a nil config)
		}
		_, err := client.PutBucketNotificationConfiguration(notificationInput)
		if err != nil {
			log.Warnf("Unable to clear S3 event notifications on bucket %s (%v). Use the console to clear.",
				*bucketName, err)
		}
		return nil
	}

	// Here there aren't too many objects, we can delete them in a handful of BatchDelete calls.
	log.Info("deleting " + uri)
	err = s3batch.DeleteObjects(client, 2*time.Minute, &s3.DeleteObjectsInput{
		Bucket: bucketName,
		Delete: &s3.Delete{Objects: objectVersions},
	})
	if err != nil {
		return fmt.Errorf("failed to batch delete objects: %v", err)
	}
	time.Sleep(time.Second) // short pause since S3 is eventually consistent to avoid next call from failing
	if _, err = client.DeleteBucket(&s3.DeleteBucketInput{Bucket: bucketName}); err != nil {
		return fmt.Errorf("failed to delete bucket %s: %v", *bucketName, err)
	}

	return nil
}
