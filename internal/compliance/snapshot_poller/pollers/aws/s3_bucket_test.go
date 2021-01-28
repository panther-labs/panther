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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestS3GetBucketLogging(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketLogging"})

	out, err := getBucketLogging(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetBucketLoggingError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketLogging"})

	out, err := getBucketLogging(mockSvc, awstest.ExampleBucketName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestS3GetBucketTagging(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketTagging"})

	out, err := getBucketTagging(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetBucketTaggingError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketTagging"})

	out, err := getBucketTagging(mockSvc, awstest.ExampleBucketName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestS3GetBucketAcl(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketAcl"})

	out, err := getBucketACL(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetBucketAclError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketAcl"})

	out, err := getBucketACL(mockSvc, awstest.ExampleBucketName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestS3GetObjectLockConfiguration(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetObjectLockConfiguration"})

	out, err := getObjectLockConfiguration(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetObjectLockConfigurationError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetObjectLockConfiguration"})

	out, err := getObjectLockConfiguration(mockSvc, awstest.ExampleBucketName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestS3BucketsList(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"ListBuckets"})

	out, err := listBuckets(mockSvc)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestS3BucketsListError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"ListBuckets"})

	out, err := listBuckets(mockSvc)
	assert.Empty(t, out)
	assert.Error(t, err)
}

func TestS3GetBucketEncryption(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketEncryption"})

	out, err := getBucketEncryption(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetBucketEncryptionError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketEncryption"})

	out, err := getBucketEncryption(mockSvc, awstest.ExampleBucketName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestS3GetBucketPolicy(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketPolicy"})

	out, err := getBucketPolicy(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetBucketPolicyError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketPolicy"})

	out, err := getBucketPolicy(mockSvc, awstest.ExampleBucketName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestS3GetBucketVersioning(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketVersioning"})

	out, err := getBucketVersioning(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetBucketVersioningError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketVersioning"})

	out, err := getBucketVersioning(mockSvc, awstest.ExampleBucketName)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestS3GetBucketLocation(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketLocation"})

	out, err := getBucketLocation(mockSvc, awstest.ExampleBucketName)
	assert.NoError(t, err)
	assert.Equal(t, "us-west-2", *out)
	assert.NotEmpty(t, out)
}

// Specifically test for buckets located in the us-east-1 region
func TestS3GetBucketLocationVirginia(t *testing.T) {
	mockSvc := &awstest.MockS3{}
	mockSvc.On("GetBucketLocation", mock.Anything).
		Return(
			&s3.GetBucketLocationOutput{
				LocationConstraint: nil,
			},
			nil,
		)

	out, err := getBucketLocation(mockSvc, awstest.ExampleBucketName)
	assert.NoError(t, err)
	assert.Equal(t, "us-east-1", *out)
	assert.NotEmpty(t, out)
}

func TestS3GetBucketLocationError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketLocation"})

	out, err := getBucketLocation(mockSvc, awstest.ExampleBucketName)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestS3GetBucketLifecycleConfiguration(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetBucketLifecycleConfiguration"})

	out, err := getBucketLifecycleConfiguration(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetPublicAccessBlock(t *testing.T) {
	mockSvc := awstest.BuildMockS3Svc([]string{"GetPublicAccessBlock"})

	out, err := getPublicAccessBlock(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestS3GetPublicAccessBlockOtherError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetPublicAccessBlock"})

	out, err := getPublicAccessBlock(mockSvc, awstest.ExampleBucketName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestS3GetPublicAccessBlockDoesNotExist(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetPublicAccessBlockDoesNotExist"})

	out, err := getPublicAccessBlock(mockSvc, awstest.ExampleBucketName)
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestS3GetPublicAccessBlockAnotherAWSErr(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetPublicAccessBlockAnotherAWSErr"})

	out, err := getPublicAccessBlock(mockSvc, awstest.ExampleBucketName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestS3GetBucketLifecycleConfigurationError(t *testing.T) {
	mockSvc := awstest.BuildMockS3SvcError([]string{"GetBucketLifecycleConfiguration"})

	out, err := getBucketLifecycleConfiguration(mockSvc, awstest.ExampleBucketName)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestS3BucketPoller(t *testing.T) {
	awstest.MockS3ForSetup = awstest.BuildMockS3SvcAll()

	S3ClientFunc = awstest.SetupMockS3

	resources, marker, err := PollS3Buckets(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	require.NotEmpty(t, resources)
	assert.Equal(t, "arn:aws:s3:::unit-test-cloudtrail-bucket", resources[0].ID)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestS3BucketPollerError(t *testing.T) {
	resetCache()
	awstest.MockS3ForSetup = awstest.BuildMockS3SvcAllError()

	S3ClientFunc = awstest.SetupMockS3

	resources, marker, err := PollS3Buckets(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Empty(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestS3BucketPollerRegionIgnoreListError(t *testing.T) {
	resetCache()
	awstest.MockS3ForSetup = awstest.BuildMockS3SvcAllError()

	S3ClientFunc = awstest.SetupMockS3
	var e *RegionIgnoreListError

	resources, marker, err := PollS3Buckets(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
		RegionIgnoreList:    []string{aws.StringValue(awstest.ExampleRegion)},
	})

	assert.Empty(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
	assert.True(t, errors.As(err, &e))
}
