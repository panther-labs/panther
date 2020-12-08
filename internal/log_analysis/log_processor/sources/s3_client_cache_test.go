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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	lru "github.com/hashicorp/golang-lru"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	integration = &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			AWSAccountID:      "1234567890123",
			S3Bucket:          "test-bucket",
			S3PrefixLogTypes:  models.S3PrefixLogtypes{{S3Prefix: "prefix", Logtypes: []string{"Log.TestType"}}},
			IntegrationType:   models.IntegrationTypeAWS3,
			LogProcessingRole: "arn:aws:iam::123456789012:role/PantherLogProcessingRole-suffix",
			IntegrationID:     "3e4b1734-e678-4581-b291-4b8a176219e9",
		},
	}
)

func TestGetS3Client(t *testing.T) {
	resetCaches()
	lambdaMock := &testutils.LambdaMock{}
	common.LambdaClient = lambdaMock

	s3Mock := &testutils.S3Mock{}
	newS3ClientFunc = func(region *string, creds *credentials.Credentials) (result s3iface.S3API) {
		return s3Mock
	}

	marshaledResult, err := jsoniter.Marshal([]*models.SourceIntegration{integration})
	require.NoError(t, err)
	lambdaOutput := &lambda.InvokeOutput{
		Payload: marshaledResult,
	}

	expectedGetBucketLocationInput := &s3.GetBucketLocationInput{Bucket: aws.String("test-bucket")}

	// First invocation should be to get the list of available sources
	lambdaMock.On("Invoke", mock.Anything).Return(lambdaOutput, nil).Once()
	// Second invocation would be to update the status
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{}, nil).Once()
	s3Mock.On("GetBucketLocation", expectedGetBucketLocationInput).Return(
		&s3.GetBucketLocationOutput{LocationConstraint: aws.String("us-west-2")}, nil).Once()

	newCredentialsFunc = func(roleArn string) *credentials.Credentials {
		return &credentials.Credentials{}
	}

	s3Object := &S3ObjectInfo{
		S3Bucket:    "test-bucket",
		S3ObjectKey: "prefix/key",
	}
	result, sourceInfo, err := getS3Client(s3Object.S3Bucket, s3Object.S3ObjectKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, models.IntegrationTypeAWS3, sourceInfo.IntegrationType)

	// Subsequent calls should use cache
	result, sourceInfo, err = getS3Client(s3Object.S3Bucket, s3Object.S3ObjectKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, models.IntegrationTypeAWS3, sourceInfo.IntegrationType)

	// verify that we have updated the source with the last time scanned status
	updateStatusInvokeInput := lambdaMock.Calls[1].Arguments.Get(0).(*lambda.InvokeInput)
	var updateStatusInput models.LambdaInput
	require.NoError(t, jsoniter.Unmarshal(updateStatusInvokeInput.Payload, &updateStatusInput))
	require.Equal(t, "3e4b1734-e678-4581-b291-4b8a176219e9", updateStatusInput.UpdateStatus.IntegrationID)
	// Verify that the status was updated within the last 1 minute
	require.True(t, updateStatusInput.UpdateStatus.LastEventReceived.After(time.Now().Add(-1*time.Minute)))

	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)
}

func TestGetS3ClientUnknownBucket(t *testing.T) {
	resetCaches()
	lambdaMock := &testutils.LambdaMock{}
	common.LambdaClient = lambdaMock

	s3Mock := &testutils.S3Mock{}
	newS3ClientFunc = func(region *string, creds *credentials.Credentials) (result s3iface.S3API) {
		return s3Mock
	}

	marshaledResult, err := jsoniter.Marshal([]*models.SourceIntegration{integration})
	require.NoError(t, err)
	lambdaOutput := &lambda.InvokeOutput{
		Payload: marshaledResult,
	}

	lambdaMock.On("Invoke", mock.Anything).Return(lambdaOutput, nil).Once()

	newCredentialsFunc = func(roleArn string) *credentials.Credentials {
		return &credentials.Credentials{}
	}

	s3Object := &S3ObjectInfo{
		S3Bucket:    "test-bucket-unknown",
		S3ObjectKey: "prefix/key",
	}

	result, sourceInfo, err := getS3Client(s3Object.S3Bucket, s3Object.S3ObjectKey)
	require.NoError(t, err)
	require.Nil(t, result)
	require.Nil(t, sourceInfo)

	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)
}

func TestGetS3ClientSourceNoPrefix(t *testing.T) {
	resetCaches()
	lambdaMock := &testutils.LambdaMock{}
	common.LambdaClient = lambdaMock

	s3Mock := &testutils.S3Mock{}
	newS3ClientFunc = func(region *string, creds *credentials.Credentials) (result s3iface.S3API) {
		return s3Mock
	}

	integration = &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			AWSAccountID:      "1234567890123",
			S3Bucket:          "test-bucket",
			LogProcessingRole: "arn:aws:iam::123456789012:role/PantherLogProcessingRole-suffix",
			IntegrationType:   models.IntegrationTypeAWS3,
			IntegrationID:     "189cddfa-6fd5-419e-8b0e-668105b67dc0",
			S3PrefixLogTypes:  models.S3PrefixLogtypes{{S3Prefix: "", Logtypes: []string{}}},
		},
	}

	marshaledResult, err := jsoniter.Marshal([]*models.SourceIntegration{integration})
	require.NoError(t, err)
	lambdaOutput := &lambda.InvokeOutput{
		Payload: marshaledResult,
	}

	// First invocation should be to get the list of available sources
	lambdaMock.On("Invoke", mock.Anything).Return(lambdaOutput, nil).Once()
	// Second invocation would be to update the status
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{}, nil).Once()

	expectedGetBucketLocationInput := &s3.GetBucketLocationInput{Bucket: aws.String("test-bucket")}
	s3Mock.On("GetBucketLocation", expectedGetBucketLocationInput).Return(
		&s3.GetBucketLocationOutput{LocationConstraint: aws.String("us-west-2")}, nil).Once()

	newCredentialsFunc = func(roleArn string) *credentials.Credentials {
		return &credentials.Credentials{}
	}

	s3Object := &S3ObjectInfo{
		S3Bucket:    "test-bucket",
		S3ObjectKey: "test",
	}

	result, sourceInfo, err := getS3Client(s3Object.S3Bucket, s3Object.S3Bucket)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, models.IntegrationTypeAWS3, sourceInfo.IntegrationType)

	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)
}

func resetCaches() {
	// resetting cache
	globalSourceCache.cacheUpdateTime = time.Unix(0, 0)
	bucketCache, _ = lru.NewARC(s3BucketLocationCacheSize)
	s3ClientCache, _ = lru.NewARC(s3ClientCacheSize)
}

func TestSourceCacheStructFind(t *testing.T) {
	cache := sourceCache{}
	now := time.Now()
	sources := []*models.SourceIntegration{
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "1",
				IntegrationType:  models.IntegrationTypeAWS3,
				S3Bucket:         "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "", Logtypes: []string{"Foo.Bar"}}},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "2",
				IntegrationType:  models.IntegrationTypeAWS3,
				S3Bucket:         "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "foo", Logtypes: []string{"Foo.Baz"}}},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:   "3",
				IntegrationType: models.IntegrationTypeAWS3,
				S3Bucket:        "foo",
				S3Prefix:        "foo/bar/sqs",
				LogTypes:        []string{"Foo.Sqs"},
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "4",
				IntegrationType:  models.IntegrationTypeAWS3,
				S3Bucket:         "foo",
				S3PrefixLogTypes: models.S3PrefixLogtypes{{S3Prefix: "foo/bar/baz", Logtypes: []string{"Foo.Qux"}}},
			},
		},
	}
	assert := require.New(t)
	cache.Update(now, sources)
	{
		src := cache.FindS3("foo", "bar")
		assert.NotNil(src)
		assert.Equal("1", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar.json")
		assert.NotNil(src)
		assert.Equal("2", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar/baz.json")
		assert.NotNil(src)
		assert.Equal("4", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar/sqs/test.json")
		assert.NotNil(src)
		assert.Equal("3", src.IntegrationID)
	}
	{
		src := cache.FindS3("foo", "foo/bar/baz/qux.json")
		assert.NotNil(src)
		assert.Equal("4", src.IntegrationID)
	}
	{
		src := cache.FindS3("goo", "foo/bar/baz/qux.json")
		assert.Nil(src)
	}
}
