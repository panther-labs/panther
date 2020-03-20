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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	// sessionDurationSeconds is the duration in seconds of the STS session the S3 client uses
	sessionDurationSeconds  = 3600
	sourceAPIFunctionName = "panther-source-api"
)

type s3ClientCacheKey struct {
	roleArn   string
	awsRegion string
}

var (
	// Bucket name -> region
	bucketCache *lru.ARCCache

	// s3ClientCacheKey -> S3 client
	s3ClientCache *lru.ARCCache

	lambdaClient lambdaiface.LambdaAPI = lambda.New(common.Session)
)



func init() {
	var err error
	s3ClientCache, err = lru.NewARC(1000)
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
func getS3Client(s3Object *S3ObjectInfo) (*s3.S3, error) {
	roleArn, err := getRoleArn(s3Object)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch the appropriate role arn to retrieve S3 object %#v", s3Object)
	}

	if roleArn == nil {
		return nil, errors.Errorf("there is no source configured for S3 object %#v", s3Object)
	}

	awsCreds := getAwsCredentials(*roleArn)
	if awsCreds == nil {
		return nil, errors.Errorf("failed to fetch credentials for assumed role to read %#v",s3Object)
	}

	bucketRegion, ok := bucketCache.Get(s3Object.S3Bucket)
	if !ok {
		zap.L().Debug("bucket region was not cached, fetching it", zap.String("bucket", s3Object.S3Bucket))
		bucketRegion, err = getBucketRegion(s3Object.S3Bucket, awsCreds)
		if err != nil {
			return nil, err
		}
		bucketCache.Add(s3Object.S3Bucket, bucketRegion)
	}

	zap.L().Debug("found bucket region", zap.Any("region", bucketRegion))

	cacheKey := s3ClientCacheKey{
		roleArn:   *roleArn,
		awsRegion: bucketRegion.(string),
	}

	var client interface{}
	client, ok = s3ClientCache.Get(cacheKey)
	if !ok {
		zap.L().Debug("s3 client was not cached, creating it")
		client = s3.New(common.Session, aws.NewConfig().
			WithRegion(bucketRegion.(string)).
			WithCredentials(awsCreds))
		s3ClientCache.Add(cacheKey, client)
	}
	return client.(*s3.S3), nil
}

func getBucketRegion(s3Bucket string, awsCreds *credentials.Credentials) (string, error) {
	zap.L().Debug("searching bucket region", zap.String("bucket", s3Bucket))

	locationDiscoveryClient := s3.New(common.Session, &aws.Config{Credentials: awsCreds})
	input := &s3.GetBucketLocationInput{Bucket: aws.String(s3Bucket)}
	location, err := locationDiscoveryClient.GetBucketLocation(input)
	if err != nil {
		return "", errors.Wrapf(err, "failed to find bucket region for %s", s3Bucket)
	}

	// Method may return nil if region is us-east-1,https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
	// and https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
	if location.LocationConstraint == nil {
		return endpoints.UsEast1RegionID, nil
	}
	return *location.LocationConstraint, nil
}

// getAwsCredentials fetches the AWS Credentials from STS for by assuming a role in the given account
func getAwsCredentials(roleArn string) *credentials.Credentials {
	zap.L().Debug("fetching new credentials from assumed role", zap.String("roleArn", roleArn))
	return stscreds.NewCredentials(common.Session, roleArn, func(p *stscreds.AssumeRoleProvider) {
		p.Duration = time.Duration(sessionDurationSeconds) * time.Second
	})
}

// Returns the appropriate role arn for a given S3 object
// It will return error if it encountered an issue retrieving the role.
// It will return nil result if role for such object doesn't exist.
func getRoleArn(s3Object *S3ObjectInfo) (*string, error) {
	input := &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{
			IntegrationType: aws.String(models.IntegrationTypeAWS3),
		},
	}
	var output []*models.SourceIntegration
	err := genericapi.Invoke(lambdaClient, sourceAPIFunctionName, input, &output)
	if err != nil {
		return nil, err
	}

	for _, integration := range output{
		if aws.StringValue(integration.S3Bucket) == s3Object.S3Bucket{
			if strings.HasPrefix(s3Object.S3ObjectKey, aws.StringValue(integration.S3Prefix)) {
				return integration.LogProcessingRole, nil
			}
		}
	}
	return nil, nil
}
