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
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/box"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	// sessionDurationSeconds is the duration in seconds of the STS session the S3 client uses
	sessionDurationSeconds = 3600
	sourceAPIFunctionName  = "panther-source-api"
	// How frequently to query the sources_api for new integrations
	sourceCacheDuration = 5 * time.Minute

	s3BucketLocationCacheSize = 1000
	s3ClientCacheSize         = 1000
)

type s3ClientCacheKey struct {
	roleArn   string
	awsRegion string
}

type sourceCacheStruct struct {
	cacheUpdateTime time.Time
	byBucket        map[string][]*models.SourceIntegration
}

func (c *sourceCacheStruct) Update(now time.Time, sources []*models.SourceIntegration) {
	byBucket := make(map[string][]*models.SourceIntegration)
	for _, source := range sources {
		bucketName, _ := getSourceS3Info(source)
		bucketSources := byBucket[bucketName]
		byBucket[bucketName] = append(bucketSources, source)
	}
	// Sort sources for each bucket
	// It is important to have the sources sorted by longest prefix first.
	// This ensures that longer prefixes (ie `/foo/bar`) have precedence over shorter ones (ie `/foo`).
	// This is especially important for the empty prefix as it would match all objects in a bucket making
	// other sources invalid.
	for bucketName, sources := range byBucket {
		sourcesSorted := sources
		sort.Slice(sourcesSorted, func(i, j int) bool {
			_, prefixA := getSourceS3Info(sourcesSorted[i])
			_, prefixB := getSourceS3Info(sourcesSorted[j])
			// Sort by prefix length descending
			return len(prefixA) > len(prefixB)
		})
		byBucket[bucketName] = sourcesSorted
	}
	*c = sourceCacheStruct{
		byBucket:        byBucket,
		cacheUpdateTime: now,
	}
}
func (c *sourceCacheStruct) Find(bucketName, objectKey string) *models.SourceIntegration {
	sources := c.byBucket[bucketName]
	for _, source := range sources {
		_, sourcePrefix := getSourceS3Info(source)
		if strings.HasPrefix(objectKey, sourcePrefix) {
			return source
		}
	}
	return nil
}

var (
	// Bucket name -> region
	bucketCache *lru.ARCCache

	// s3ClientCacheKey -> S3 client
	s3ClientCache *lru.ARCCache

	sourceCache = &sourceCacheStruct{
		cacheUpdateTime: time.Unix(0, 0),
	}

	//used to simplify mocking during testing
	newCredentialsFunc = stscreds.NewCredentials
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
func getS3Client(s3Object *S3ObjectInfo) (s3iface.S3API, *models.SourceIntegration, error) {
	sourceInfo, err := getSourceInfo(s3Object)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to fetch the appropriate role arn to retrieve S3 object %#v", s3Object)
	}

	if sourceInfo == nil {
		return nil, nil, errors.Errorf("there is no source configured for S3 object %#v", s3Object)
	}
	var awsCreds *credentials.Credentials // lazy create below
	roleArn := getSourceLogProcessingRole(sourceInfo)

	bucketRegion, ok := bucketCache.Get(s3Object.S3Bucket)
	if !ok {
		zap.L().Debug("bucket region was not cached, fetching it", zap.String("bucket", s3Object.S3Bucket))
		awsCreds = getAwsCredentials(roleArn)
		if awsCreds == nil {
			return nil, nil, errors.Errorf("failed to fetch credentials for assumed role %s to read %#v",
				roleArn, s3Object)
		}
		bucketRegion, err = getBucketRegion(s3Object.S3Bucket, awsCreds)
		if err != nil {
			return nil, nil, err
		}
		bucketCache.Add(s3Object.S3Bucket, bucketRegion)
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
			awsCreds = getAwsCredentials(roleArn)
			if awsCreds == nil {
				return nil, nil, errors.Errorf("failed to fetch credentials for assumed role %s to read %#v",
					roleArn, s3Object)
			}
		}
		client = newS3ClientFunc(box.String(cacheKey.awsRegion), awsCreds)
		s3ClientCache.Add(cacheKey, client)
	}
	return client.(s3iface.S3API), sourceInfo, nil
}

func getBucketRegion(s3Bucket string, awsCreds *credentials.Credentials) (string, error) {
	zap.L().Debug("searching bucket region", zap.String("bucket", s3Bucket))

	locationDiscoveryClient := newS3ClientFunc(nil, awsCreds)
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
	return newCredentialsFunc(common.Session, roleArn, func(p *stscreds.AssumeRoleProvider) {
		p.Duration = time.Duration(sessionDurationSeconds) * time.Second
		p.ExpiryWindow = time.Minute // give plenty of time to refresh
	})
}

// Returns the source configuration for this S3 object.
// It will return error if it encountered an issue retrieving the role.
// It will return nil result if no source exists for this object.
func getSourceInfo(s3Object *S3ObjectInfo) (result *models.SourceIntegration, err error) {
	now := time.Now() // No need to be UTC. We care about relative time
	if sourceCache.cacheUpdateTime.Add(sourceCacheDuration).Before(now) {
		// we need to update the cache
		input := &models.LambdaInput{
			ListIntegrations: &models.ListIntegrationsInput{},
		}
		var output []*models.SourceIntegration
		err = genericapi.Invoke(common.LambdaClient, sourceAPIFunctionName, input, &output)
		if err != nil {
			return nil, err
		}
		sourceCache.Update(now, output)
	}

	result = sourceCache.Find(s3Object.S3Bucket, s3Object.S3ObjectKey)

	// If the incoming notification maps to a known source, update the source information
	if result != nil {
		deadline := lastEventReceived[result.IntegrationID].Add(statusUpdateFrequency)
		// if more than 'statusUpdateFrequency' time has passed, update status
		if now.After(deadline) {
			updateIntegrationStatus(result.IntegrationID, now)
			lastEventReceived[result.IntegrationID] = now
		}
	}

	return result, nil
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
	return s3.New(common.Session, config)
}

// Returns the configured S3 bucket and S3 object prefix for this source
func getSourceS3Info(source *models.SourceIntegration) (string, string) {
	switch source.IntegrationType {
	case models.IntegrationTypeSqs:
		return source.SqsConfig.S3Bucket, source.SqsConfig.S3Prefix
	default:
		return source.S3Bucket, source.S3Prefix
	}
}

func getSourceLogProcessingRole(source *models.SourceIntegration) (roleArn string) {
	switch source.IntegrationType {
	case models.IntegrationTypeAWS3:
		roleArn = source.LogProcessingRole
	case models.IntegrationTypeSqs:
		roleArn = source.SqsConfig.LogProcessingRole
	}
	return roleArn
}
