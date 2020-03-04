package aws

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

var (
	// S3BucketSnapshots is a mapping between bucket name and its snapshot.
	S3BucketSnapshots map[string]*awsmodels.S3Bucket
	// S3ClientFunc is the function to initialize the S3 Client.
	S3ClientFunc = setupS3Client
)

func setupS3BucketSnapshots() {
	S3BucketSnapshots = make(map[string]*awsmodels.S3Bucket)
}

func setupS3Client(sess *session.Session, cfg *aws.Config) interface{} {
	cfg.MaxRetries = aws.Int(MaxRetries)
	return s3.New(sess, cfg)
}

// PollS3Bucket polls a single S3 Bucket resource
func PollS3Bucket(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) interface{} {

	client := getClient(pollerResourceInput, "s3", defaultRegion).(s3iface.S3API)
	region := getBucketLocation(client, aws.String(resourceARN.Resource))
	if region == nil {
		return nil
	}
	client = getClient(pollerResourceInput, "s3", *region).(s3iface.S3API)
	bucket := getBucket(client, resourceARN.Resource)

	snapshot := buildS3BucketSnapshot(client, bucket)
	if snapshot == nil {
		return nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(pollerResourceInput.AuthSourceParsedARN.AccountID)
	snapshot.Region = region
	snapshot.ARN = scanRequest.ResourceID
	return snapshot
}

// getBucket returns a specific S3 bucket
func getBucket(svc s3iface.S3API, bucketName string) *s3.Bucket {
	zap.L().Debug("looking for bucket", zap.String("bucket", bucketName))
	buckets := listBuckets(svc)
	if buckets == nil {
		return nil
	}
	for _, bucket := range buckets.Buckets {
		if aws.StringValue(bucket.Name) == bucketName {
			return bucket
		}
	}
	return nil
}

// getBucketLogging returns the logging policy for a given S3 bucket, and nil if one is not set
func getBucketLogging(s3Svc s3iface.S3API, bucketName *string) (*s3.GetBucketLoggingOutput, error) {
	in := &s3.GetBucketLoggingInput{Bucket: bucketName}

	out, err := s3Svc.GetBucketLogging(in)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// getObjectLockConfiguration returns the object lock configuration for an S3 bucket, if one exists
func getObjectLockConfiguration(s3Svc s3iface.S3API, bucketName *string) (*s3.ObjectLockConfiguration, error) {
	out, err := s3Svc.GetObjectLockConfiguration(&s3.GetObjectLockConfigurationInput{Bucket: bucketName})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "ObjectLockConfigurationNotFoundError" {
				zap.L().Debug("no object lock configuration found", zap.String("bucket", *bucketName))
				return nil, err
			}
		}
		utils.LogAWSError("S3.GetObjectLockConfiguration", err)

		return nil, err
	}

	return out.ObjectLockConfiguration, nil
}

// getBucketTagging returns the tags for a given S3 bucket
func getBucketTagging(s3Svc s3iface.S3API, bucketName *string) ([]*s3.Tag, error) {
	tags, err := s3Svc.GetBucketTagging(&s3.GetBucketTaggingInput{Bucket: bucketName})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "NoSuchTagSet" {
				zap.L().Debug("no tags found", zap.String("bucket", *bucketName))
				return nil, err
			}
		}
		utils.LogAWSError("S3.GetBucketTagging", err)
		return nil, err
	}

	return tags.TagSet, nil
}

// getBucketEncryption returns a list of server-side encryption settings for a given S3 bucket
func getBucketEncryption(
	s3Svc s3iface.S3API,
	bucketName *string,
) ([]*s3.ServerSideEncryptionRule, error) {

	in := &s3.GetBucketEncryptionInput{Bucket: bucketName}
	out, err := s3Svc.GetBucketEncryption(in)
	if err != nil {
		return nil, err
	}

	return out.ServerSideEncryptionConfiguration.Rules, nil
}

// getBucketPolicy returns the bucket policy of the given bucket as a JSON formatted string
func getBucketPolicy(s3Svc s3iface.S3API, bucketName *string) (*string, error) {
	in := &s3.GetBucketPolicyInput{Bucket: bucketName}
	out, err := s3Svc.GetBucketPolicy(in)
	if err != nil {
		return nil, err
	}

	return out.Policy, nil
}

// getBucketVersioning returns version information for a given s3 bucket
func getBucketVersioning(s3Svc s3iface.S3API, bucketName *string) (*s3.GetBucketVersioningOutput, error) {
	in := &s3.GetBucketVersioningInput{Bucket: bucketName}
	out, err := s3Svc.GetBucketVersioning(in)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// getBucketLocation returns the region a bucket resides in
func getBucketLocation(s3Svc s3iface.S3API, bucketName *string) *string {
	in := &s3.GetBucketLocationInput{Bucket: bucketName}
	out, err := s3Svc.GetBucketLocation(in)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "NoSuchBucket" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *bucketName),
					zap.String("resourceType", awsmodels.S3BucketSchema))
				return nil
			}
		}
		return nil
	}

	// The get-bucket-location API call returns null for buckets in us-east-1. This behavior is not documented by AWS.
	if out.LocationConstraint == nil {
		return aws.String("us-east-1")
	}

	return out.LocationConstraint
}

// getBucketLifecycle returns lifecycle configuration information set on a given bucket
func getBucketLifecycleConfiguration(s3Svc s3iface.S3API, bucketName *string) ([]*s3.LifecycleRule, error) {
	in := &s3.GetBucketLifecycleConfigurationInput{Bucket: bucketName}
	out, err := s3Svc.GetBucketLifecycleConfiguration(in)
	if err != nil {
		return nil, err
	}

	return out.Rules, nil
}

// getBucketACL returns all ACLs for a given S3 bucket.
func getBucketACL(s3Svc s3iface.S3API, bucketName *string) (*s3.GetBucketAclOutput, error) {
	in := &s3.GetBucketAclInput{Bucket: bucketName}
	out, err := s3Svc.GetBucketAcl(in)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// listS3Buckets returns a list of all S3 buckets in an account
func listBuckets(s3Svc s3iface.S3API) *s3.ListBucketsOutput {
	in := &s3.ListBucketsInput{}
	out, err := s3Svc.ListBuckets(in)
	if err != nil {
		utils.LogAWSError("S3.ListBuckets", err)
		return nil
	}

	return out
}

// getPublicAccessBlock retrieves the PublicAccessBlock configuration for an Amazon S3 bucket
func getPublicAccessBlock(
	s3Svc s3iface.S3API,
	bucketName *string,
) (*s3.PublicAccessBlockConfiguration, error) {

	out, err := s3Svc.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{
		Bucket: bucketName,
	})

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			case "NoSuchPublicAccessBlockConfiguration":
				zap.L().Debug(
					"no public access block configuration found", zap.String("bucketName", *bucketName))
				return nil, nil
			default:
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return out.PublicAccessBlockConfiguration, nil
}

func buildS3BucketSnapshot(s3Svc s3iface.S3API, bucket *s3.Bucket) *awsmodels.S3Bucket {
	if bucket == nil {
		return nil
	}
	s3Snapshot := &awsmodels.S3Bucket{
		GenericResource: awsmodels.GenericResource{
			TimeCreated:  utils.DateTimeFormat(*bucket.CreationDate),
			ResourceType: aws.String(awsmodels.S3BucketSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name: bucket.Name,
		},
	}

	// Get the acls for each bucket
	bucketAcls, err := getBucketACL(s3Svc, bucket.Name)
	if err != nil {
		utils.LogAWSError("S3.GetBucketACL", err)
	} else {
		s3Snapshot.Owner = bucketAcls.Owner
		s3Snapshot.Grants = bucketAcls.Grants
	}

	tags, err := getBucketTagging(s3Svc, bucket.Name)
	if err == nil {
		s3Snapshot.Tags = utils.ParseTagSlice(tags)
	}

	objectLockConfiguration, err := getObjectLockConfiguration(s3Svc, bucket.Name)
	if err == nil {
		s3Snapshot.ObjectLockConfiguration = objectLockConfiguration
	}

	// These api calls check on S3 bucket features which may have no value set.
	// They return an error when that feature is not set, so we DEBUG log the error message here.
	loggingPolicy, err := getBucketLogging(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("S3.GetBucketLogging", zap.Error(err))
	} else {
		s3Snapshot.LoggingPolicy = loggingPolicy.LoggingEnabled
	}

	versioning, err := getBucketVersioning(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("S3.GetBucketVersioning", zap.Error(err))
	} else {
		s3Snapshot.Versioning = versioning.Status
		s3Snapshot.MFADelete = versioning.MFADelete
	}

	// TODO: Check all API calls below for expected errors (when configs do not exist)
	// 			 and return an error if an unexpected one is returned.
	lifecycleRules, err := getBucketLifecycleConfiguration(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("no bucket lifecycle configuration set", zap.Error(err))
	} else {
		s3Snapshot.LifecycleRules = lifecycleRules
	}

	encryption, err := getBucketEncryption(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("no bucket encryption set", zap.Error(err))
	} else {
		s3Snapshot.EncryptionRules = encryption
	}

	policy, err := getBucketPolicy(s3Svc, bucket.Name)
	if err != nil {
		zap.L().Debug("no bucket policy set", zap.Error(err))
	} else {
		s3Snapshot.Policy = policy
	}

	blockConfig, err := getPublicAccessBlock(s3Svc, bucket.Name)
	if err != nil {
		utils.LogAWSError("S3.GetPublicAccessBlock", err)
	} else {
		s3Snapshot.PublicAccessBlockConfiguration = blockConfig
	}

	return s3Snapshot
}

// PollS3Buckets gathers information on each S3 bucket for an AWS account.
func PollS3Buckets(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting S3 Bucket resource poller", zap.String("integrationID", *pollerInput.IntegrationID))

	// Clear the previously collected S3 Bucket Snapshots
	setupS3BucketSnapshots()

	sess := session.Must(session.NewSession(&aws.Config{}))
	creds, err := AssumeRoleFunc(pollerInput, sess)
	if err != nil {
		return nil, err
	}

	s3Svc := S3ClientFunc(sess, &aws.Config{Credentials: creds}).(s3iface.S3API)

	// Start with generating a list of all buckets
	allBuckets := listBuckets(s3Svc)
	if allBuckets == nil {
		zap.L().Debug("nothing returned by S3 list buckets")
		return nil, nil
	}
	zap.L().Debug("listed all S3 buckets", zap.Int("count", len(allBuckets.Buckets)))

	// For each bucket, determine its region, then group it with other buckets in that region
	// so a session can be created for each region to build the snapshots. Only pay attention to
	// buckets from active regions/regions the user has requested.
	bucketsByRegion := map[string][]*s3.Bucket{}
	for _, region := range pollerInput.Regions {
		bucketsByRegion[*region] = []*s3.Bucket{}
	}

	for _, bucket := range allBuckets.Buckets {
		if bucket == nil {
			zap.L().Debug("nil bucket returned by S3 list buckets")
			continue
		}
		region := getBucketLocation(s3Svc, bucket.Name)
		if region == nil {
			continue
		}

		if regionBuckets, ok := bucketsByRegion[*region]; ok {
			bucketsByRegion[*region] = append(regionBuckets, bucket)
		}
	}

	var resources []*apimodels.AddResourceEntry
	for region, buckets := range bucketsByRegion {
		// Build session for this region
		// TODO possible optimization by not building us-west-2 since it's already built
		buildSess := session.Must(session.NewSession(&aws.Config{Region: aws.String(region)}))
		buildCreds, err := AssumeRoleFunc(pollerInput, buildSess)
		if err != nil {
			zap.L().Error(
				"error assuming role for S3 snapshot building",
				zap.String("region", region),
				zap.Error(err),
			)
			continue
		}
		buildConfig := &aws.Config{Credentials: buildCreds}
		buildSvc := S3ClientFunc(buildSess, buildConfig).(s3iface.S3API)

		for _, bucket := range buckets {
			s3BucketSnapshot := buildS3BucketSnapshot(buildSvc, bucket)

			resourceID := strings.Join(
				[]string{"arn", pollerInput.AuthSourceParsedARN.Partition, "s3::", *s3BucketSnapshot.Name},
				":",
			)

			// Populate generic fields
			s3BucketSnapshot.ResourceID = aws.String(resourceID)

			// Populate AWS generic fields
			s3BucketSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			s3BucketSnapshot.ARN = aws.String(resourceID)
			s3BucketSnapshot.Region = aws.String(region)

			S3BucketSnapshots[*s3BucketSnapshot.Name] = s3BucketSnapshot

			resources = append(resources, &apimodels.AddResourceEntry{
				Attributes:      s3BucketSnapshot,
				ID:              apimodels.ResourceID(resourceID),
				IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
				IntegrationType: apimodels.IntegrationTypeAws,
				Type:            awsmodels.S3BucketSchema,
			})
		}
	}

	return resources, nil
}
