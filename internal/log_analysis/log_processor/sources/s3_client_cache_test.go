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
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
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
			AWSAccountID:      aws.String("1234567890123"),
			S3Bucket:          aws.String("test-bucket"),
			S3Prefix:          aws.String("prefix"),
			IntegrationType:   aws.String(models.IntegrationTypeAWS3),
			LogProcessingRole: aws.String("arn:aws:iam::123456789012:role/PantherLogProcessingRole-suffix"),
			IntegrationID:     aws.String("3e4b1734-e678-4581-b291-4b8a176219e9"),
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

	newCredentialsFunc =
		func(c client.ConfigProvider, roleARN string, options ...func(*stscreds.AssumeRoleProvider)) *credentials.Credentials {
			return &credentials.Credentials{}
		}

	s3Object := &S3ObjectInfo{
		S3Bucket:    "test-bucket",
		S3ObjectKey: "prefix/key",
	}
	result, sourceType, err := getS3Client(s3Object)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, models.IntegrationTypeAWS3, sourceType)

	// Subsequent calls should use cache
	result, sourceType, err = getS3Client(s3Object)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, models.IntegrationTypeAWS3, sourceType)

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

	newCredentialsFunc =
		func(c client.ConfigProvider, roleARN string, options ...func(*stscreds.AssumeRoleProvider)) *credentials.Credentials {
			return &credentials.Credentials{}
		}

	s3Object := &S3ObjectInfo{
		S3Bucket:    "test-bucket-unknown",
		S3ObjectKey: "prefix/key",
	}

	result, sourceType, err := getS3Client(s3Object)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, "", sourceType)

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
			AWSAccountID:      aws.String("1234567890123"),
			S3Bucket:          aws.String("test-bucket"),
			LogProcessingRole: aws.String("arn:aws:iam::123456789012:role/PantherLogProcessingRole-suffix"),
			IntegrationType:   aws.String(models.IntegrationTypeAWS3),
			IntegrationID:     aws.String("189cddfa-6fd5-419e-8b0e-668105b67dc0"),
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

	newCredentialsFunc =
		func(c client.ConfigProvider, roleARN string, options ...func(*stscreds.AssumeRoleProvider)) *credentials.Credentials {
			return &credentials.Credentials{}
		}

	s3Object := &S3ObjectInfo{
		S3Bucket:    "test-bucket",
		S3ObjectKey: "test",
	}

	result, sourceType, err := getS3Client(s3Object)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, models.IntegrationTypeAWS3, sourceType)

	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)
}

func resetCaches() {
	// resetting cache
	sourceCache.cacheUpdateTime = time.Unix(0, 0)
	bucketCache, _ = lru.NewARC(s3BucketLocationCacheSize)
	s3ClientCache, _ = lru.NewARC(s3ClientCacheSize)
}
