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
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	// sessionDuration is the duration of S3 client STS session
	sessionDuration = time.Hour
	// Expirty window for the STS credentials.
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

type sourceCache struct {
	// last time the cache was updated
	cacheUpdateTime time.Time
	// prefixes by s3 bucket. Each prefixes array is ordered by longest first.
	// An s3 source may have many prefixes, that's why we can't just directly map from bucket to source.
	prefixesByBucket map[string][]string
	sourceByPrefix   map[string]*models.SourceIntegration
	sourceByID       map[string]*models.SourceIntegration
}

// LoadS3 loads the source configuration for an S3 object.
// This will update the cache if needed.
// It will return error if it encountered an issue retrieving the source information
func (c *sourceCache) LoadS3(bucketName, objectKey string) (*models.SourceIntegration, error) {
	if err := c.Sync(time.Now()); err != nil {
		return nil, err
	}
	return c.FindS3(bucketName, objectKey), nil
}

// Loads the source configuration for an source id.
// This will update the cache if needed.
// It will return error if it encountered an issue retrieving the source information or if the source is not found.
func (c *sourceCache) Load(id string) (*models.SourceIntegration, error) {
	if err := c.Sync(time.Now()); err != nil {
		return nil, err
	}
	src := c.Find(id)
	if src != nil {
		return src, nil
	}
	return nil, errors.Errorf("source %q not found", id)
}

// Sync will update the cache if too much time has passed
func (c *sourceCache) Sync(now time.Time) error {
	if c.cacheUpdateTime.Add(sourceCacheDuration).Before(now) {
		// we need to update the cache
		input := &models.LambdaInput{
			ListIntegrations: &models.ListIntegrationsInput{},
		}
		var output []*models.SourceIntegration
		if err := genericapi.Invoke(common.LambdaClient, sourceAPIFunctionName, input, &output); err != nil {
			return err
		}
		c.Update(now, output)
	}
	return nil
}

// Update updates the cache
func (c *sourceCache) Update(now time.Time, sources []*models.SourceIntegration) {
	prefixesByBucket := make(map[string][]string)
	sourceByPrefix := make(map[string]*models.SourceIntegration)
	sourceByID := make(map[string]*models.SourceIntegration)

	for _, source := range sources {
		sourceByID[source.IntegrationID] = source
		sourceBucket, sourcePrefixes := source.S3Info()
		for _, prefix := range sourcePrefixes {
			prefixesByBucket[sourceBucket] = append(prefixesByBucket[sourceBucket], prefix)
			sourceByPrefix[prefix] = source
		}
	}

	// Sort sources for each bucket
	// It is important to have the sources sorted by longest prefix first.
	// This ensures that longer prefixes (ie `/foo/bar`) have precedence over shorter ones (ie `/foo`).
	// This is especially important for the empty prefix as it would match all objects in a bucket making
	// other sources invalid.
	for _, prefixes := range prefixesByBucket {
		prefixes := prefixes
		sort.Slice(prefixes, func(i, j int) bool {
			return len(prefixes[i]) > len(prefixes[j])
		})
	}
	*c = sourceCache{
		prefixesByBucket: prefixesByBucket,
		sourceByPrefix:   sourceByPrefix,
		sourceByID:       sourceByID,
		cacheUpdateTime:  now,
	}
}

// Find looks up a source by id without updating the cache
func (c *sourceCache) Find(id string) *models.SourceIntegration {
	return c.sourceByID[id]
}

// FindS3 looks up a source by bucket name and prefix without updating the cache
func (c *sourceCache) FindS3(bucket, objectKey string) *models.SourceIntegration {
	for _, prefix := range c.prefixesByBucket[bucket] {
		if strings.HasPrefix(objectKey, prefix) {
			return c.sourceByPrefix[prefix]
		}
	}
	return nil
}

var (
	// Bucket name -> region
	bucketCache *lru.ARCCache

	// s3ClientCacheKey -> S3 client
	s3ClientCache *lru.ARCCache

	globalSourceCache = &sourceCache{}

	//used to simplify mocking during testing
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
	// We have seen that in some case AWS will return AccessDenied while accessing data
	// through STS creds. The issue seems to disappear after some retries
	awsSession := session.Must(session.NewSession(config)) // use default retries for fetching creds, avoids hangs!
	return s3.New(awsSession.Copy(request.WithRetryer(config.WithMaxRetries(s3ClientMaxRetries),
		awsretry.NewAccessDeniedRetryer(s3ClientMaxRetries))))
}