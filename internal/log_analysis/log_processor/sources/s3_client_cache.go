package sources

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
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/s3"
	lru "github.com/hashicorp/golang-lru"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
)

const (
	// sessionDurationSeconds is the duration in seconds of the STS session the S3 client uses
	sessionDurationSeconds  = 3600
	logProcessingRoleFormat = "arn:aws:iam::%s:role/PantherLogProcessingRole"
)

var (
	// Bucket name -> region
	bucketCache *lru.ARCCache

	// region -> S3 client
	s3ClientCache *lru.ARCCache
)

type s3ClientCacheKey struct {
	awsAccountID string
	awsRegion    string
}

func init() {
	var err error
	s3ClientCache, err = lru.NewARC(100)
	if err != nil {
		panic("Failed to create client cache")
	}

	bucketCache, err = lru.NewARC(1000)
	if err != nil {
		panic("Failed to create bucket cache")
	}
}

// getS3Client Fetches S3 client with permissions to read data from the account
// that owns the SNS Topic
func getS3Client(s3Bucket string, topicArn string) (*s3.S3, error) {
	parsedTopicArn, err := arn.Parse(topicArn)
	if err != nil {
		return nil, err
	}

	awsCreds := getAwsCredentials(parsedTopicArn.AccountID)
	if awsCreds == nil {
		return nil, errors.New("failed to fetch credentials for assumed role")
	}

	bucketRegion, ok := bucketCache.Get(s3Bucket)
	if !ok {
		zap.L().Info("bucket region was not cached, fetching it", zap.String("bucket", s3Bucket))
		bucketRegion, err = getBucketRegion(s3Bucket, awsCreds)
		if err != nil {
			return nil, err
		}
		bucketCache.Add(s3Bucket, bucketRegion)
	}

	zap.L().Debug("found bucket region", zap.Any("region", bucketRegion))

	cacheKey := s3ClientCacheKey{
		awsAccountID: parsedTopicArn.AccountID,
		awsRegion:    bucketRegion.(string),
	}

	var client interface{}
	client, ok = s3ClientCache.Get(cacheKey)
	if !ok {
		zap.L().Info("s3 client was not cached, creating it")
		client = s3.New(common.Session, aws.NewConfig().
			WithRegion(bucketRegion.(string)).
			WithCredentials(awsCreds))
		s3ClientCache.Add(cacheKey, client)
	}
	return client.(*s3.S3), nil
}

func getBucketRegion(s3Bucket string, awsCreds *credentials.Credentials) (string, error) {
	zap.L().Debug("searching bucket region",
		zap.String("bucket", s3Bucket))

	locationDiscoveryClient := s3.New(common.Session, &aws.Config{Credentials: awsCreds})
	input := &s3.GetBucketLocationInput{Bucket: aws.String(s3Bucket)}
	location, err := locationDiscoveryClient.GetBucketLocation(input)
	if err != nil {
		zap.L().Warn("failed to find bucket region", zap.Error(err))
		return "", err
	}

	// Method may return nil if region is us-east-1,https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
	// and https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
	if location.LocationConstraint == nil {
		return endpoints.UsEast1RegionID, nil
	}
	return *location.LocationConstraint, nil
}

// getAwsCredentials fetches the AWS Credentials from STS for by assuming a role in the given account
func getAwsCredentials(awsAccountID string) *credentials.Credentials {
	roleArn := fmt.Sprintf(logProcessingRoleFormat, awsAccountID)
	zap.L().Debug("fetching new credentials from assumed role", zap.String("roleArn", roleArn))

	return stscreds.NewCredentials(common.Session, roleArn, func(p *stscreds.AssumeRoleProvider) {
		p.Duration = time.Duration(sessionDurationSeconds) * time.Second
	})
}
