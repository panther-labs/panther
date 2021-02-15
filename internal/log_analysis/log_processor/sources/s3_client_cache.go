package sources

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/awsretry"
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	// sessionDuration is the duration of S3 client STS session
	sessionDuration = time.Hour
	// Expiry window for the STS credentials.
	// Give plenty of time for refresh, we have seen that 1 minute refresh time can sometimes lead to InvalidAccessKeyId errors
	sessionExpiryWindow   = 2 * time.Minute
	sourceAPIFunctionName = "panther-source-api"
	// How frequently to query the panther-sources-api for new integrations
	sourceCacheDuration = 2 * time.Minute

	s3BucketLocationCacheSize = 1000
	s3ClientCacheSize         = 1000
	s3ClientMaxRetries        = 10 // ~1'
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

	globalSourceCache = &sourceCache{}

	// used to simplify mocking during testing
	newCredentialsFunc = getAwsCredentials
	newS3ClientFunc    = getNewS3Client

	// Map from integrationId -> last time an event was received
	lastEventReceived = make(map[string]time.Time)
	// How frequently to update the status
	statusUpdateFrequency = 1 * time.Minute
)

func init() {
	var err error
	s3ClientCache, err = lru.NewARC(s3ClientCacheSize)
	if err != nil {
		panic("Failed to create client cache")
	}

	bucketCache, err = lru.NewARC(s3BucketLocationCacheSize)
	if err != nil {
		panic("Failed to create bucket cache")
	}
}

// getS3Client Fetches
// 1. S3 client with permissions to read data from the account that contains the event
// 2. The source integration
func getS3Client(bucketName, objectKey string) (s3iface.S3API, *models.SourceIntegration, error) {
	source, err := LoadSourceS3(bucketName, objectKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to fetch the appropriate role arn to retrieve S3 object %s/%s", bucketName, objectKey)
	}

	if source == nil {
		return nil, nil, nil
	}
	var awsCreds *credentials.Credentials // lazy create below
	roleArn := source.RequiredLogProcessingRole()

	bucketRegion, ok := bucketCache.Get(bucketName)
	if !ok {
		zap.L().Debug("bucket region was not cached, fetching it", zap.String("bucket", bucketName))
		awsCreds = newCredentialsFunc(roleArn)
		if awsCreds == nil {
			return nil, nil, errors.Errorf("failed to fetch credentials for assumed role %s to read %s/%s",
				roleArn, bucketName, objectKey)
		}
		bucketRegion, err = getBucketRegion(bucketName, awsCreds)
		if err != nil {
			return nil, nil, err
		}
		bucketCache.Add(bucketName, bucketRegion)
	}

	zap.L().Debug("found bucket region", zap.Any("region", bucketRegion))

	cacheKey := s3ClientCacheKey{
		roleArn:   roleArn,
		awsRegion: bucketRegion.(string),
	}
	client, ok := s3ClientCache.Get(cacheKey)
	if !ok {
		zap.L().Debug("s3 client was not cached, creating it")
		if awsCreds == nil {
			awsCreds = newCredentialsFunc(roleArn)
			if awsCreds == nil {
				return nil, nil, errors.Errorf("failed to fetch credentials for assumed role %s to read %s/%s",
					roleArn, bucketName, objectKey)
			}
		}
		client = newS3ClientFunc(&cacheKey.awsRegion, awsCreds)
		s3ClientCache.Add(cacheKey, client)
	}
	return client.(s3iface.S3API), source, nil
}

func getBucketRegion(s3Bucket string, awsCreds *credentials.Credentials) (string, error) {
	zap.L().Debug("searching bucket region", zap.String("bucket", s3Bucket))

	locationDiscoveryClient := newS3ClientFunc(nil, awsCreds)
	input := &s3.GetBucketLocationInput{Bucket: aws.String(s3Bucket)}
	location, err := locationDiscoveryClient.GetBucketLocationWithContext(context.TODO(), input)
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
	// Use regional STS endpoints as per AWS recommendation https://docs.aws.amazon.com/general/latest/gr/sts.html
	credsSession := common.Session.Copy(aws.NewConfig().WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint))
	return stscreds.NewCredentials(credsSession, roleArn, func(p *stscreds.AssumeRoleProvider) {
		p.Duration = sessionDuration
		p.ExpiryWindow = sessionExpiryWindow
	})
}

func updateIntegrationStatus(integrationID string, timestamp time.Time) {
	input := &models.LambdaInput{
		UpdateStatus: &models.UpdateStatusInput{
			IntegrationID:     integrationID,
			LastEventReceived: timestamp,
		},
	}
	// We are setting the `output` parameter to `nil` since we don't care about the returned value
	err := genericapi.Invoke(common.LambdaClient, sourceAPIFunctionName, input, nil)
	// best effort - if we fail to update the status, just log a warning
	if err != nil {
		zap.L().Warn("failed to update status for integrationID", zap.String("integrationID", integrationID))
	}
}

func getNewS3Client(region *string, creds *credentials.Credentials) (result s3iface.S3API) {
	config := aws.NewConfig().WithCredentials(creds)
	if region != nil {
		config.WithRegion(*region)
	}
	awsSession := session.Must(session.NewSession(config)) // use default retries for fetching creds, avoids hangs!
	s3Client := s3.New(awsSession.Copy(request.WithRetryer(config.WithMaxRetries(s3ClientMaxRetries),
		awsretry.NewConnectionErrRetryer(s3ClientMaxRetries))))
	return &RefreshableS3Client{
		S3API: s3Client,
		creds: creds,
	}
}

// Wrapper around S3 client. It will refresh credentials in case `InvalidAccessKeyId` error is encountered
type RefreshableS3Client struct {
	s3iface.S3API
	creds *credentials.Credentials
}

// This error code will appear if the IAM role assumed by Panther log processing is deleted and recreated.
// When we try to perform operations to S3, we will get an error that the AKID is invalid
const invalidAKIDError = "InvalidAccessKeyId"

func (r *RefreshableS3Client) GetBucketLocationWithContext(
	ctx aws.Context,
	request *s3.GetBucketLocationInput,
	options ...request.Option) (*s3.GetBucketLocationOutput, error) {

	response, err := r.S3API.GetBucketLocationWithContext(ctx, request, options...)
	if awsutils.IsAnyError(err, invalidAKIDError) {
		zap.L().Debug("encountered error, refreshing S3 client credentials", zap.Error(err))
		r.creds.Expire()
		response, err = r.S3API.GetBucketLocationWithContext(ctx, request, options...)
	}
	return response, err
}

func (r *RefreshableS3Client) GetObjectWithContext(
	ctx aws.Context,
	request *s3.GetObjectInput,
	options ...request.Option) (*s3.GetObjectOutput, error) {

	response, err := r.S3API.GetObjectWithContext(ctx, request, options...)
	if awsutils.IsAnyError(err, invalidAKIDError) {
		zap.L().Debug("encountered error, refreshing S3 client credentials", zap.Error(err))
		r.creds.Expire()
		response, err = r.S3API.GetObjectWithContext(ctx, request, options...)
	}
	return response, err
}
