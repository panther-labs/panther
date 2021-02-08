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
	"path/filepath"
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
	// Expiry window for the STS credentials.
	// Give plenty of time for refresh, we have seen that 1 minute refresh time can sometimes lead to InvalidAccessKeyId errors
	sessionExpiryWindow   = 2 * time.Minute
	sourceAPIFunctionName = "panther-source-api"
	// How frequently to query the panther-sources-api for new integrations
	sourceCacheDuration = 2 * time.Minute

	s3BucketLocationCacheSize = 1000
	s3ClientCacheSize         = 1000
	s3ClientMaxRetries        = 10 // ~1'
	s3ClientMaxRetriesOnError = 0  // if a previous use of a s3 the prefix failed, only retry this many times
)

type s3ClientCacheKey struct {
	roleArn   string
	awsRegion string
}

type prefixSource struct {
	prefix string
	source *models.SourceIntegration
}

type sourceCache struct {
	// last time the cache was updated
	cacheUpdateTime time.Time
	// sources by id
	index map[string]*models.SourceIntegration
	// sources by s3 bucket sorted by longest prefix first
	byBucket map[string][]prefixSource
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
	byBucket := make(map[string][]prefixSource)
	index := make(map[string]*models.SourceIntegration)
	for _, source := range sources {
		bucket, prefixes := source.S3Info()
		for _, prefix := range prefixes {
			byBucket[bucket] = append(byBucket[bucket], prefixSource{prefix: prefix, source: source})
		}
		index[source.IntegrationID] = source
	}
	// Sort sources for each bucket.
	// It is important to have the sources sorted by longest prefix first.
	// This ensures that longer prefixes (ie `/foo/bar`) have precedence over shorter ones (ie `/foo`).
	// This is especially important for the empty prefix as it would match all objects in a bucket making
	// other sources invalid.
	for _, sources := range byBucket {
		sources := sources
		sort.Slice(sources, func(i, j int) bool {
			// Sort by prefix length descending
			return len(sources[i].prefix) > len(sources[j].prefix)
		})
	}
	*c = sourceCache{
		byBucket:        byBucket,
		index:           index,
		cacheUpdateTime: now,
	}
}

// Find looks up a source by id without updating the cache
func (c *sourceCache) Find(id string) *models.SourceIntegration {
	return c.index[id]
}

// FindS3 looks up a source by bucket name and prefix without updating the cache
func (c *sourceCache) FindS3(bucketName, objectKey string) *models.SourceIntegration {
	prefixSourcesOrdered := c.byBucket[bucketName]
	for _, s := range prefixSourcesOrdered {
		if strings.HasPrefix(objectKey, s.prefix) {
			return s.source
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
func getS3Client(bucketName, objectKey string) (S3Reader, *models.SourceIntegration, error) {
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
		locationDiscoveryClient, err := getCachedClient(roleArn, bucketName, "", objectKey, awsCreds)
		if err != nil {
			return nil, nil, err
		}
		bucketRegion, err = getBucketRegion(bucketName, locationDiscoveryClient)
		if err != nil {
			return nil, nil, err
		}
		bucketCache.Add(bucketName, bucketRegion)
	}

	zap.L().Debug("found bucket region", zap.Any("region", bucketRegion))
	client, err := getCachedClient(roleArn, bucketName, bucketRegion.(string), objectKey, awsCreds)
	return client, source, err
}

func getCachedClient(roleArn, bucketName, bucketRegion, objectKey string, awsCreds *credentials.Credentials) (S3Reader, error) {
	cacheKey := s3ClientCacheKey{
		roleArn:   roleArn,
		awsRegion: bucketRegion,
	}
	client, ok := s3ClientCache.Get(cacheKey)
	if !ok {
		zap.L().Debug("s3 client was not cached, creating it")
		if awsCreds == nil {
			awsCreds = newCredentialsFunc(roleArn)
			if awsCreds == nil {
				return nil, errors.Errorf("failed to fetch credentials for assumed role %s to read %s/%s",
					roleArn, bucketName, objectKey)
			}
		}
		client = newS3ClientFunc(&cacheKey.awsRegion, awsCreds)
		s3ClientCache.Add(cacheKey, client)
	}
	return client.(S3Reader), nil
}

func getBucketRegion(s3Bucket string, client S3Reader) (string, error) {
	zap.L().Debug("searching bucket region", zap.String("bucket", s3Bucket))

	input := &s3.GetBucketLocationInput{Bucket: aws.String(s3Bucket)}
	var locationClient s3iface.S3API = client
	if client.HasFailedObjectPrefix(s3Bucket, "") {
		locationClient = client.FailedReadObjectClient()
	}
	location, err := locationClient.GetBucketLocation(input)
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

type S3Reader interface {
	s3iface.S3API
	FailedReadObjectClient() s3iface.S3API
	AddFailedObjectPrefix(bucket, key string)
	HasFailedObjectPrefix(bucket, key string) bool
}

// S3ReaderClient wraps the S3 client and tracks prefixes with repeated errors. If an s3 object being read
// has a prefix in the map of previously failed objects then the downloader will use the failedReadObjectClient
// to read the file which has a much lower retry count. This avoids the lambda spending large amounts
// of time retrying when permissions are not set properly on buckets (which can last hours or days sometimes).
type S3ReaderClient struct {
	s3.S3
	failedReadObjectPrefixes map[string]struct{} // remember the S3 folders that fail
	failedReadObjectClient   s3iface.S3API       // the client to use if path is in failedReadObjectPrefixes, lower retries!
}

func (c *S3ReaderClient) FailedReadObjectClient() s3iface.S3API {
	return c.failedReadObjectClient
}

func (c *S3ReaderClient) AddFailedObjectPrefix(bucket, key string) {
	c.failedReadObjectPrefixes[failedPath(bucket, key)] = struct{}{}
}

func (c *S3ReaderClient) HasFailedObjectPrefix(bucket, key string) bool {
	_, found := c.failedReadObjectPrefixes[failedPath(bucket, key)]
	return found
}

func failedPath(bucket, key string) string {
	// take at most top n dirs in path, including bucket
	const n = 3
	parts := []string{bucket}
	dir := filepath.Dir(key)
	if dir != "." {
		parts = append(parts, strings.Split(dir, "/")...)
	}
	if len(parts) > n {
		parts = parts[0:n]
	}
	return strings.Join(parts, "/")
}

func getNewS3Client(region *string, creds *credentials.Credentials) S3Reader {
	config := aws.NewConfig().WithCredentials(creds)
	if region != nil {
		config.WithRegion(*region)
	}
	// We have seen that in some case AWS will return AccessDenied while accessing data
	// through STS creds. The issue seems to disappear after some retries
	awsSession := session.Must(session.NewSession(config)) // use default retries for fetching creds, avoids hangs!
	return &S3ReaderClient{
		S3: *s3.New(awsSession.Copy(request.WithRetryer(config.WithMaxRetries(s3ClientMaxRetries),
			awsretry.NewAccessDeniedRetryer(s3ClientMaxRetries)))),
		failedReadObjectPrefixes: make(map[string]struct{}),
		failedReadObjectClient: s3.New(awsSession.Copy(request.WithRetryer(config.WithMaxRetries(s3ClientMaxRetriesOnError),
			awsretry.NewAccessDeniedRetryer(s3ClientMaxRetriesOnError)))),
	}
}
