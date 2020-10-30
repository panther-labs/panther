package awstest

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
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/mock"
)

var (
	//
	// Example S3 Buckets
	//

	ExampleS3Owner = &s3.Owner{
		DisplayName: aws.String("root.user"),
		ID:          aws.String("555555eeeeee41f994e6151b666666f2a69149f2935670e702fa919eaf77777d"),
	}

	ExampleBucketAcl = &s3.GetBucketAclOutput{
		Grants: []*s3.Grant{
			{
				Grantee: &s3.Grantee{
					DisplayName:  aws.String("root.user"),
					EmailAddress: aws.String("root.user@test.io"),
					ID:           aws.String("555555eeeeee41f994e6151b666666f2a69149f2935670e702fa919eaf77777d"),
					Type:         aws.String("CanonicalUser"),
				},
				Permission: aws.String("FULL_CONTROL"),
			},
		},
		Owner: ExampleS3Owner,
	}

	ExampleBucketName = aws.String("random-identifier-us-west-2")

	ExampleBuckets = []*s3.Bucket{
		{
			Name:         aws.String("unit-test-cloudtrail-bucket"),
			CreationDate: &ExampleTime,
		},
	}

	ExampleListBuckets = &s3.ListBucketsOutput{
		Buckets: ExampleBuckets,
		Owner:   ExampleS3Owner,
	}

	ExampleBucketLogging = &s3.GetBucketLoggingOutput{
		LoggingEnabled: &s3.LoggingEnabled{
			TargetBucket: aws.String("random-target-us-west-2"),
			TargetPrefix: aws.String(""),
		},
	}

	ExampleGetBucketEncryptionOutput = &s3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &s3.ServerSideEncryptionConfiguration{
			Rules: []*s3.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &s3.ServerSideEncryptionByDefault{
						SSEAlgorithm: aws.String("AES256"),
					},
				},
			},
		},
	}

	ExampleGetBucketVersioningOutput = &s3.GetBucketVersioningOutput{
		MFADelete: aws.String("Enabled"),
		Status:    aws.String("Enabled"),
	}

	ExampleGetBucketLocationOutput = &s3.GetBucketLocationOutput{
		LocationConstraint: aws.String("us-west-2"),
	}

	ExampleGetBucketLifecycleConfigurationOutput = &s3.GetBucketLifecycleConfigurationOutput{
		Rules: []*s3.LifecycleRule{
			{
				AbortIncompleteMultipartUpload: &s3.AbortIncompleteMultipartUpload{
					DaysAfterInitiation: aws.Int64(7),
				},
				Expiration: &s3.LifecycleExpiration{
					Days: aws.Int64(180),
				},
				Filter: &s3.LifecycleRuleFilter{
					Prefix: aws.String(""),
				},
				ID:     aws.String("Polling-Testing-Rule"),
				Status: aws.String("Enabled"),
			},
		},
	}

	ExampleBucketPolicy = &s3.GetBucketPolicyOutput{
		Policy: aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::cloudtrail-bucket-name\"},{\"Sid\":\"AWSCloudTrailWrite\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":[\"arn:aws:s3:::cloudtrail-bucket-name/AWSLogs/123456789012/*\"],\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"),
	}

	ExampleBucketPublicAccessBlockConfig = &s3.GetPublicAccessBlockOutput{
		PublicAccessBlockConfiguration: &s3.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	}

	ExampleGetBucketTagging = &s3.GetBucketTaggingOutput{
		TagSet: []*s3.Tag{
			{
				Key:   aws.String("Key1"),
				Value: aws.String("Value1"),
			},
		},
	}

	ExampleGetObjectLockConfiguration = &s3.GetObjectLockConfigurationOutput{
		ObjectLockConfiguration: &s3.ObjectLockConfiguration{
			ObjectLockEnabled: aws.String("Enabled"),
		},
	}

	svcS3SetupCalls = map[string]func(*MockS3){
		"GetBucketLogging": func(svc *MockS3) {
			svc.On("GetBucketLogging", mock.Anything).
				Return(ExampleBucketLogging, nil)
		},
		"GetBucketAcl": func(svc *MockS3) {
			svc.On("GetBucketAcl", mock.Anything).
				Return(ExampleBucketAcl, nil)
		},
		"ListBuckets": func(svc *MockS3) {
			svc.On("ListBuckets", mock.Anything).
				Return(ExampleListBuckets, nil)
		},
		"GetBucketEncryption": func(svc *MockS3) {
			svc.On("GetBucketEncryption", mock.Anything).
				Return(ExampleGetBucketEncryptionOutput, nil)
		},
		"GetBucketPolicy": func(svc *MockS3) {
			svc.On("GetBucketPolicy", mock.Anything).
				Return(ExampleBucketPolicy, nil)
		},
		"GetBucketVersioning": func(svc *MockS3) {
			svc.On("GetBucketVersioning", mock.Anything).
				Return(ExampleGetBucketVersioningOutput, nil)
		},
		"GetBucketLocation": func(svc *MockS3) {
			svc.On("GetBucketLocation", mock.Anything).
				Return(ExampleGetBucketLocationOutput, nil)
		},
		"GetBucketLifecycleConfiguration": func(svc *MockS3) {
			svc.On("GetBucketLifecycleConfiguration", mock.Anything).
				Return(ExampleGetBucketLifecycleConfigurationOutput, nil)
		},
		"GetPublicAccessBlock": func(svc *MockS3) {
			svc.On("GetPublicAccessBlock", mock.Anything).
				Return(ExampleBucketPublicAccessBlockConfig, nil)
		},
		"GetBucketTagging": func(svc *MockS3) {
			svc.On("GetBucketTagging", mock.Anything).
				Return(ExampleGetBucketTagging, nil)
		},
		"GetObjectLockConfiguration": func(svc *MockS3) {
			svc.On("GetObjectLockConfiguration", mock.Anything).
				Return(ExampleGetObjectLockConfiguration, nil)
		},
	}

	svcS3SetupCallsError = map[string]func(*MockS3){
		"GetBucketLogging": func(svc *MockS3) {
			svc.On("GetBucketLogging", mock.Anything).
				Return(
					&s3.GetBucketLoggingOutput{},
					errors.New("S3.GetBucketLogging error"),
				)
		},
		"GetBucketAcl": func(svc *MockS3) {
			svc.On("GetBucketAcl", mock.Anything).
				Return(
					&s3.GetBucketAclOutput{},
					errors.New("S3.GetBucketAcl error"),
				)
		},
		"ListBuckets": func(svc *MockS3) {
			svc.On("ListBuckets", mock.Anything).
				Return(
					&s3.ListBucketsOutput{},
					errors.New("S3.ListBuckets error"),
				)
		},
		"GetBucketEncryption": func(svc *MockS3) {
			svc.On("GetBucketEncryption", mock.Anything).
				Return(
					&s3.GetBucketEncryptionOutput{},
					errors.New("S3.GetEncryption error"),
				)
		},
		"GetBucketPolicy": func(svc *MockS3) {
			svc.On("GetBucketPolicy", mock.Anything).
				Return(
					&s3.GetBucketPolicyOutput{},
					errors.New("S3.GetPolicy error"),
				)
		},
		"GetBucketVersioning": func(svc *MockS3) {
			svc.On("GetBucketVersioning", mock.Anything).
				Return(
					&s3.GetBucketVersioningOutput{},
					errors.New("S3.GetVersioning error"),
				)
		},
		"GetBucketLocation": func(svc *MockS3) {
			svc.On("GetBucketLocation", mock.Anything).
				Return(
					&s3.GetBucketLocationOutput{},
					errors.New("S3.GetLocation error"),
				)
		},
		"GetBucketLifecycleConfiguration": func(svc *MockS3) {
			svc.On("GetBucketLifecycleConfiguration", mock.Anything).
				Return(
					&s3.GetBucketLifecycleConfigurationOutput{},
					errors.New("S3.GetLifecycleConfiguration error"),
				)
		},
		"GetPublicAccessBlock": func(svc *MockS3) {
			svc.On("GetPublicAccessBlock", mock.Anything).
				Return(
					&s3.GetPublicAccessBlockOutput{},
					errors.New("S3.GetPublicAccessBlock error"),
				)
		},
		"GetPublicAccessBlockAnotherAWSErr": func(svc *MockS3) {
			svc.On("GetPublicAccessBlock", mock.Anything).
				Return(
					&s3.GetPublicAccessBlockOutput{},
					awserr.New(
						"InvalidBucketName",
						"The bucket name is invalid",
						errors.New("fake getPublicAccessBlock error"),
					),
				)
		},
		"GetPublicAccessBlockDoesNotExist": func(svc *MockS3) {
			svc.On("GetPublicAccessBlock", mock.Anything).
				Return(
					&s3.GetPublicAccessBlockOutput{},
					awserr.New(
						"NoSuchPublicAccessBlockConfiguration",
						"The public access block configuration was not found",
						errors.New("fake getPublicAccessBlock error"),
					),
				)
		},
		"GetBucketTagging": func(svc *MockS3) {
			svc.On("GetBucketTagging", mock.Anything).
				Return(
					&s3.GetBucketTaggingOutput{},
					errors.New("S3.GetBucketTagging error"),
				)
		},
		"GetObjectLockConfiguration": func(svc *MockS3) {
			svc.On("GetObjectLockConfiguration", mock.Anything).
				Return(
					&s3.GetObjectLockConfigurationOutput{},
					errors.New("S3.GetObjectLockConfiguration error"),
				)
		},
	}

	MockS3ForSetup = &MockS3{}
)

// S3 mock

// SetupMockS3 is used to override the S3 Client initializer.
func SetupMockS3(_ *session.Session, _ *aws.Config) interface{} {
	return MockS3ForSetup
}

// MockS3 is a mock S3 client.
type MockS3 struct {
	s3iface.S3API
	mock.Mock
}

// BuildMockS3Svc builds and returns a MockS3 struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockS3Svc(funcs []string) (mockSvc *MockS3) {
	mockSvc = &MockS3{}
	for _, f := range funcs {
		svcS3SetupCalls[f](mockSvc)
	}
	return
}

// BuildMockS3SvcError builds and returns a MockS3 struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockS3SvcError(funcs []string) (mockSvc *MockS3) {
	mockSvc = &MockS3{}
	for _, f := range funcs {
		svcS3SetupCallsError[f](mockSvc)
	}
	return
}

// BuildMockS3SvcAll builds and returns a MockS3 struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockS3SvcAll() (mockSvc *MockS3) {
	mockSvc = &MockS3{}
	for _, f := range svcS3SetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockS3SvcAllError builds and returns a MockS3 struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockS3SvcAllError() (mockSvc *MockS3) {
	mockSvc = &MockS3{}
	for _, f := range svcS3SetupCallsError {
		f(mockSvc)
	}
	return
}

// GetBucketAcl is a mock function to return fake S3 Bucket ACL data.
func (m *MockS3) GetBucketAcl(in *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketAclOutput), args.Error(1)
}

// GetBucketLogging is a mock function to return fake S3 Bucket Logging data.
func (m *MockS3) GetBucketLogging(in *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketLoggingOutput), args.Error(1)
}

// ListBuckets is a mock function to return fake S3 bucket data
func (m *MockS3) ListBuckets(in *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.ListBucketsOutput), args.Error(1)
}

// GetBucketPolicy is a mock function to return fake S3 Bucket Policy data.
func (m *MockS3) GetBucketPolicy(in *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketPolicyOutput), args.Error(1)
}

// GetBucketEncryption is a mock function to return fake S3 Bucket encryption data.
func (m *MockS3) GetBucketEncryption(in *s3.GetBucketEncryptionInput) (*s3.GetBucketEncryptionOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketEncryptionOutput), args.Error(1)
}

// GetBucketVersioning is a mock function to return fake S3 Bucket versioning data.
func (m *MockS3) GetBucketVersioning(in *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketVersioningOutput), args.Error(1)
}

// GetBucketLocation is a mock function to return fake S3 Bucket location data.
func (m *MockS3) GetBucketLocation(in *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketLocationOutput), args.Error(1)
}

// GetBucketLifecycleConfiguration is a mock function to return fake S3 Bucket lifecycle configuration data.
func (m *MockS3) GetBucketLifecycleConfiguration(
	in *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketLifecycleConfigurationOutput), args.Error(1)
}

// GetPublicAccessBlock is a mock function to return fake S3 public access block data.
func (m *MockS3) GetPublicAccessBlock(in *s3.GetPublicAccessBlockInput) (*s3.GetPublicAccessBlockOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetPublicAccessBlockOutput), args.Error(1)
}

func (m *MockS3) GetBucketTagging(in *s3.GetBucketTaggingInput) (*s3.GetBucketTaggingOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetBucketTaggingOutput), args.Error(1)
}

func (m *MockS3) GetObjectLockConfiguration(in *s3.GetObjectLockConfigurationInput) (*s3.GetObjectLockConfigurationOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*s3.GetObjectLockConfigurationOutput), args.Error(1)
}
