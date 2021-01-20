package aws

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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

var (
	// S3ClientFunc is the function to initialize the S3 Client.
	S3ClientFunc = setupS3Client
)

func setupS3Client(sess *session.Session, cfg *aws.Config) interface{} {
	return s3.New(sess, cfg)
}

func getS3Client(pollerResourceInput *awsmodels.ResourcePollerInput, region string, resourceARN *arn.ARN) (s3iface.S3API, error) {
	// Saves an unnecessary check
	if resourceARN != nil {
		// Check if ResourceID matches the integration's regex filter
		if pollerResourceInput.ShouldIgnoreResource(resourceARN.String()) {
			return nil, nil
		}
	}

	client, err := getClient(pollerResourceInput, S3ClientFunc, "s3", region)
	if err != nil {
		return nil, err
	}

	return client.(s3iface.S3API), nil
}

// PollS3Bucket polls a single S3 Bucket resource
func PollS3Bucket(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	locationClient, err := getS3Client(pollerResourceInput, defaultRegion, &resourceARN)
	if err != nil {
		return nil, err
	}
	// May return nil, nil if bucket no longer exists
	region, err := getBucketLocation(locationClient, aws.String(resourceARN.Resource))
	if err != nil || region == nil {
		return nil, err
	}

	regionalClient, err := getS3Client(pollerResourceInput, *region, nil)
	if err != nil {
		return nil, err
	}

	bucket, err := getBucket(regionalClient, resourceARN.Resource)
	if err != nil {
		return nil, err
	}

	// May return nil, nil if bucket no longer exists
	snapshot, err := buildS3BucketSnapshot(regionalClient, bucket)
	if err != nil || snapshot == nil {
		return nil, err
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(pollerResourceInput.AuthSourceParsedARN.AccountID)
	snapshot.Region = region
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getBucket returns a specific S3 bucket
func getBucket(svc s3iface.S3API, bucketName string) (*s3.Bucket, error) {
	// This horribly inefficient bucket lookup is required because (to my knowledge) there is no other
	// way to get the bucket creation time.
	buckets, err := listBuckets(svc)
	if err != nil || buckets == nil {
		return nil, errors.WithMessagef(err, "single resource scan for bucket %s", bucketName)
	}
	for _, bucket := range buckets.Buckets {
		if aws.StringValue(bucket.Name) == bucketName {
			return bucket, nil
		}
	}
	return nil, nil
}

// getBucketLogging returns the logging policy for a given S3 bucket, and nil if one is not set
func getBucketLogging(s3Svc s3iface.S3API, bucketName *string) (*s3.GetBucketLoggingOutput, error) {
	out, err := s3Svc.GetBucketLogging(&s3.GetBucketLoggingInput{Bucket: bucketName})
	if err != nil {
		return nil, errors.Wrapf(err, "S3.GetBucketLogging: %s", aws.StringValue(bucketName))
	}

	return out, nil
}

// getObjectLockConfiguration returns the object lock configuration for an S3 bucket, if one exists
func getObjectLockConfiguration(s3Svc s3iface.S3API, bucketName *string) (*s3.ObjectLockConfiguration, error) {
	out, err := s3Svc.GetObjectLockConfiguration(&s3.GetObjectLockConfigurationInput{Bucket: bucketName})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "ObjectLockConfigurationNotFoundError" {
			zap.L().Debug("no object lock configuration found", zap.String("bucket", *bucketName))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "S3.GetObjectLockConfiguration: %s", aws.StringValue(bucketName))
	}

	return out.ObjectLockConfiguration, nil
}

// getBucketTagging returns the tags for a given S3 bucket
func getBucketTagging(s3Svc s3iface.S3API, bucketName *string) ([]*s3.Tag, error) {
	tags, err := s3Svc.GetBucketTagging(&s3.GetBucketTaggingInput{Bucket: bucketName})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "NoSuchTagSet" {
			zap.L().Debug("no tags found", zap.String("bucket", *bucketName))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "S3.GetBucketTagging: %s", aws.StringValue(bucketName))
	}

	return tags.TagSet, nil
}

// getBucketEncryption returns a list of server-side encryption settings for a given S3 bucket
func getBucketEncryption(s3Svc s3iface.S3API, bucketName *string) ([]*s3.ServerSideEncryptionRule, error) {
	out, err := s3Svc.GetBucketEncryption(&s3.GetBucketEncryptionInput{Bucket: bucketName})
	if err != nil {
		return nil, errors.Wrapf(err, "S3.GetBucketEncryption: %s", aws.StringValue(bucketName))
	}

	return out.ServerSideEncryptionConfiguration.Rules, nil
}

// getBucketPolicy returns the bucket policy of the given bucket as a JSON formatted string
func getBucketPolicy(s3Svc s3iface.S3API, bucketName *string) (*string, error) {
	out, err := s3Svc.GetBucketPolicy(&s3.GetBucketPolicyInput{Bucket: bucketName})
	if err != nil {
		return nil, errors.Wrapf(err, "S3.GetBucketPolicy: %s", aws.StringValue(bucketName))
	}

	return out.Policy, nil
}

// getBucketVersioning returns version information for a given s3 bucket
func getBucketVersioning(s3Svc s3iface.S3API, bucketName *string) (*s3.GetBucketVersioningOutput, error) {
	out, err := s3Svc.GetBucketVersioning(&s3.GetBucketVersioningInput{Bucket: bucketName})
	if err != nil {
		return nil, errors.Wrapf(err, "S3.GetBucketVersioning: %s", aws.StringValue(bucketName))
	}

	return out, nil
}

// getBucketLocation returns the region a bucket resides in
func getBucketLocation(s3Svc s3iface.S3API, bucketName *string) (*string, error) {
	out, err := s3Svc.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: bucketName})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == s3.ErrCodeNoSuchBucket {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *bucketName),
				zap.String("resourceType", awsmodels.S3BucketSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "S3.GetBucketLocation: %s", aws.StringValue(bucketName))
	}

	// The get-bucket-location API call returns null for buckets in us-east-1.
	if out.LocationConstraint == nil {
		return aws.String("us-east-1"), nil
	}

	return out.LocationConstraint, nil
}

// getBucketLifecycle returns lifecycle configuration information set on a given bucket
func getBucketLifecycleConfiguration(s3Svc s3iface.S3API, bucketName *string) ([]*s3.LifecycleRule, error) {
	out, err := s3Svc.GetBucketLifecycleConfiguration(&s3.GetBucketLifecycleConfigurationInput{Bucket: bucketName})
	if err != nil {
		return nil, errors.Wrapf(err, "GetBucketLifecycleConfiguration: %s", aws.StringValue(bucketName))
	}

	return out.Rules, nil
}

// getBucketACL returns all ACLs for a given S3 bucket.
func getBucketACL(s3Svc s3iface.S3API, bucketName *string) (*s3.GetBucketAclOutput, error) {
	out, err := s3Svc.GetBucketAcl(&s3.GetBucketAclInput{Bucket: bucketName})
	if err != nil {
		return nil, errors.Wrapf(err, "S3.GetBucketACL: %s", aws.StringValue(bucketName))
	}

	return out, nil
}

// listS3Buckets returns a list of all S3 buckets in an account
func listBuckets(s3Svc s3iface.S3API) (*s3.ListBucketsOutput, error) {
	buckets, err := s3Svc.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return nil, errors.Wrap(err, "S3.ListBuckets")
	}
	return buckets, nil
}

// getPublicAccessBlock retrieves the PublicAccessBlock configuration for an Amazon S3 bucket
func getPublicAccessBlock(s3Svc s3iface.S3API, bucketName *string) (*s3.PublicAccessBlockConfiguration, error) {
	out, err := s3Svc.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{Bucket: bucketName})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "NoSuchPublicAccessBlockConfiguration" {
			zap.L().Debug(
				"no public access block configuration found", zap.String("bucketName", *bucketName))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "S3.GetPublicAccessBlock: %s", aws.StringValue(bucketName))
	}

	return out.PublicAccessBlockConfiguration, nil
}

func buildS3BucketSnapshot(s3Svc s3iface.S3API, bucket *s3.Bucket) (*awsmodels.S3Bucket, error) {
	if bucket == nil {
		return nil, nil
	}
	s3Snapshot := &awsmodels.S3Bucket{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  bucket.CreationDate,
			ResourceType: aws.String(awsmodels.S3BucketSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name: bucket.Name,
		},
	}

	// Get the acls for each bucket
	bucketAcls, err := getBucketACL(s3Svc, bucket.Name)
	if err != nil {
		return nil, err
	}
	s3Snapshot.Owner = bucketAcls.Owner
	s3Snapshot.Grants = bucketAcls.Grants

	tags, err := getBucketTagging(s3Svc, bucket.Name)
	if err != nil {
		return nil, err
	}
	if tags != nil {
		s3Snapshot.Tags = utils.ParseTagSlice(tags)
	}

	objectLockConfiguration, err := getObjectLockConfiguration(s3Svc, bucket.Name)
	if err != nil {
		return nil, err
	}
	s3Snapshot.ObjectLockConfiguration = objectLockConfiguration

	blockConfig, err := getPublicAccessBlock(s3Svc, bucket.Name)
	if err != nil {
		return nil, err
	}
	s3Snapshot.PublicAccessBlockConfiguration = blockConfig

	// These api calls check on S3 bucket features which may have no value set.
	// They return an error when that feature is not set, so we DEBUG log the error message here.
	// TODO: Check all API calls below for expected errors (when configs do not exist)
	//   and return an error if an unexpected one is returned (as above in getPublicAccessBlock).
	loggingPolicy, err := getBucketLogging(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("S3.GetBucketLogging", zap.Error(err), zap.String("bucketName", *bucket.Name))
	} else {
		s3Snapshot.LoggingPolicy = loggingPolicy.LoggingEnabled
	}

	versioning, err := getBucketVersioning(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("S3.GetBucketVersioning", zap.Error(err), zap.String("bucketName", *bucket.Name))
	} else {
		s3Snapshot.Versioning = versioning.Status
		s3Snapshot.MFADelete = versioning.MFADelete
	}

	lifecycleRules, err := getBucketLifecycleConfiguration(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("no bucket lifecycle configuration set", zap.Error(err), zap.String("bucketName", *bucket.Name))
	} else {
		s3Snapshot.LifecycleRules = lifecycleRules
	}

	encryption, err := getBucketEncryption(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("no bucket encryption set", zap.Error(err), zap.String("bucketName", *bucket.Name))
	} else {
		s3Snapshot.EncryptionRules = encryption
	}

	policy, err := getBucketPolicy(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("no bucket policy set", zap.Error(err), zap.String("bucketName", *bucket.Name))
	} else {
		s3Snapshot.Policy = policy
	}

	return s3Snapshot, nil
}

// PollS3Buckets gathers information on each S3 bucket for an AWS account.
func PollS3Buckets(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting S3 Bucket resource poller")
	s3Svc, err := getS3Client(pollerInput, *pollerInput.Region, nil)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all buckets
	allBuckets, err := listBuckets(s3Svc)
	if err != nil || len(allBuckets.Buckets) == 0 {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// For each bucket, determine its region, then only consider the bucket if it's region matches
	// the requested region. May have timeout issues for accounts with lots of buckets, but the s3
	// API is pretty limited in dealing with these things.
	var buckets []*s3.Bucket
	for _, bucket := range allBuckets.Buckets {
		if bucket == nil {
			zap.L().Debug("nil bucket returned by S3 list buckets")
			continue
		}
		// Check if ResourceID matches the integration's regex filter
		if pollerInput.ShouldIgnoreResource(*bucket.Name) {
			continue
		}
		region, err := getBucketLocation(s3Svc, bucket.Name)
		if err != nil {
			return nil, nil, err
		}
		// This may occur if the bucket stopped existing between the call to list buckets and the
		// call to get bucket location
		if region == nil {
			continue
		}

		if *region == *pollerInput.Region {
			buckets = append(buckets, bucket)
		}
	}

	var resources []apimodels.AddResourceEntry
	for _, bucket := range buckets {
		s3BucketSnapshot, err := buildS3BucketSnapshot(s3Svc, bucket)
		if err != nil {
			return nil, nil, err
		}
		resourceID := strings.Join(
			[]string{"arn", pollerInput.AuthSourceParsedARN.Partition, "s3::", *s3BucketSnapshot.Name},
			":",
		)

		// Populate generic fields
		s3BucketSnapshot.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		s3BucketSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		s3BucketSnapshot.ARN = aws.String(resourceID)
		s3BucketSnapshot.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      s3BucketSnapshot,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.S3BucketSchema,
		})
	}

	// s3 buckets can never paginate
	return resources, nil, nil
}
