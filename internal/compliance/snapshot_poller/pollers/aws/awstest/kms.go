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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/stretchr/testify/mock"
)

// Example KMS API return values
var (
	ExampleKeyId = aws.String("188c57ed-b28a-4c0e-9821-f4940d15cb0a")

	ExampleListKeysOutput = &kms.ListKeysOutput{
		Keys: []*kms.KeyListEntry{
			{
				KeyArn: aws.String("arn:aws:kms:us-west-2:111111111111:key/188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
				KeyId:  aws.String("188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
			},
			{
				KeyArn: aws.String("arn:aws:kms:us-west-2:111111111111:key/d15a1e37-3ef7-4882-9be5-ef3a024114db"),
				KeyId:  aws.String("d15a1e37-3ef7-4882-9be5-ef3a024114db"),
			},
		},
	}

	ExampleListKeysOutputContinue = &kms.ListKeysOutput{
		Keys: []*kms.KeyListEntry{
			{
				KeyArn: aws.String("arn:aws:kms:us-west-2:111111111111:key/188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
				KeyId:  aws.String("188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
			},
			{
				KeyArn: aws.String("arn:aws:kms:us-west-2:111111111111:key/d15a1e37-3ef7-4882-9be5-ef3a024114db"),
				KeyId:  aws.String("d15a1e37-3ef7-4882-9be5-ef3a024114db"),
			},
		},
		NextMarker: aws.String("1"),
	}

	ExampleGetKeyRotationStatusOutput = &kms.GetKeyRotationStatusOutput{
		KeyRotationEnabled: aws.Bool(true),
	}

	ExampleDescribeKeyOutput = &kms.DescribeKeyOutput{
		KeyMetadata: &kms.KeyMetadata{
			AWSAccountId: aws.String("111111111111"),
			Arn:          aws.String("arn:aws:kms:us-west-2:111111111111:key/188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
			CreationDate: &ExampleTime,
			Description:  aws.String("Encryption key for panther-snapshot-queue data"),
			Enabled:      aws.Bool(true),
			KeyId:        aws.String("188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
			KeyManager:   aws.String("CUSTOMER"),
			KeyState:     aws.String("Enabled"),
			KeyUsage:     aws.String("ENCRYPT_DECRYPT"),
			Origin:       aws.String("AWS_KMS"),
		},
	}

	ExampleDescribeKeyOutputAWSManaged = &kms.DescribeKeyOutput{
		KeyMetadata: &kms.KeyMetadata{
			AWSAccountId: aws.String("123456789012"),
			Arn:          aws.String("arn:aws:kms:us-west-2:111111111111:key/188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
			CreationDate: &ExampleTime,
			Description:  aws.String("Default master key"),
			Enabled:      aws.Bool(true),
			KeyId:        aws.String("188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
			KeyManager:   aws.String("AWS"),
			KeyState:     aws.String("Enabled"),
			KeyUsage:     aws.String("ENCRYPT_DECRYPT"),
			Origin:       aws.String("AWS_KMS"),
		},
	}

	ExampleGetKeyPolicyOutput = &kms.GetKeyPolicyOutput{
		Policy: aws.String("{\n  \"Version\" : \"2012-10-17\",\n  \"Id\" : \"auto-awslambda\",\n  \"Statement\" : [ {\n    \"Sid\" : \"Allow access through AWS Lambda for all principals in the account that are authorized to use AWS Lambda\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : {\n      \"AWS\" : \"*\"\n    },\n    \"Action\" : [ \"kms:Encrypt\", \"kms:Decrypt\", \"kms:ReEncrypt*\", \"kms:GenerateDataKey*\", \"kms:CreateGrant\", \"kms:DescribeKey\" ],\n    \"Resource\" : \"*\",\n    \"Condition\" : {\n      \"StringEquals\" : {\n        \"kms:CallerAccount\" : \"111111111111\",\n        \"kms:ViaService\" : \"lambda.us-west-2.amazonaws.com\"\n      }\n    }\n  }, {\n    \"Sid\" : \"Allow direct access to key metadata to the account\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : {\n      \"AWS\" : \"arn:aws:iam::111111111111:root\"\n    },\n    \"Action\" : \"kms:Describe*\",\n    \"Resource\" : \"*\"\n  } ]\n}"),
	}

	ExampleListResourceTags = &kms.ListResourceTagsOutput{
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("Key1"),
				TagValue: aws.String("Value1"),
			},
		},
	}

	svcKmsSetupCalls = map[string]func(*MockKms){
		"ListKeysPages": func(svc *MockKms) {
			svc.On("ListKeysPages", mock.Anything).
				Return(nil)
		},
		"GetKeyRotationStatus": func(svc *MockKms) {
			svc.On("GetKeyRotationStatus", mock.Anything).
				Return(ExampleGetKeyRotationStatusOutput, nil)
		},
		"DescribeKey": func(svc *MockKms) {
			svc.On("DescribeKey", mock.Anything).
				Return(ExampleDescribeKeyOutput, nil)
		},
		"GetKeyPolicy": func(svc *MockKms) {
			svc.On("GetKeyPolicy", mock.Anything).
				Return(ExampleGetKeyPolicyOutput, nil)
		},
		"ListResourceTags": func(svc *MockKms) {
			svc.On("ListResourceTags", mock.Anything).
				Return(ExampleListResourceTags, nil)
		},
	}

	svcKmsSetupCallsError = map[string]func(*MockKms){
		"ListKeysPages": func(svc *MockKms) {
			svc.On("ListKeysPages", mock.Anything).
				Return(errors.New("KMS.ListKeys error"))
		},
		"GetKeyRotationStatus": func(svc *MockKms) {
			svc.On("GetKeyRotationStatus", mock.Anything).
				Return(&kms.GetKeyRotationStatusOutput{},
					errors.New("KMS.GetKeyRotationStatus error"),
				)
		},
		"DescribeKey": func(svc *MockKms) {
			svc.On("DescribeKey", mock.Anything).
				Return(&kms.DescribeKeyOutput{},
					errors.New("KMS.DescribeKey error"),
				)
		},
		"GetKeyPolicy": func(svc *MockKms) {
			svc.On("GetKeyPolicy", mock.Anything).
				Return(&kms.GetKeyPolicyOutput{},
					errors.New("KMS.GetKeyPolicy error"),
				)
		},
		"ListResourceTags": func(svc *MockKms) {
			svc.On("ListResourceTags", mock.Anything).
				Return(&kms.ListResourceTagsOutput{},
					errors.New("KMS.ListResourceTags error"),
				)
		},
	}

	MockKmsForSetup = &MockKms{}
)

// KMS mock

// SetupMockKms is used to override the KMS Client initializer
func SetupMockKms(_ *session.Session, _ *aws.Config) interface{} {
	return MockKmsForSetup
}

// MockKms is a mock KMS client
type MockKms struct {
	kmsiface.KMSAPI
	mock.Mock
}

// BuildMockKmsSvc builds and returns a MockKms struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockKmsSvc(funcs []string) (mockSvc *MockKms) {
	mockSvc = &MockKms{}
	for _, f := range funcs {
		svcKmsSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockKmsSvcError builds and returns a MockKms struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockKmsSvcError(funcs []string) (mockSvc *MockKms) {
	mockSvc = &MockKms{}
	for _, f := range funcs {
		svcKmsSetupCallsError[f](mockSvc)
	}
	return
}

// BuildKmsServiceSvcAll builds and returns a MockKms struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockKmsSvcAll() (mockSvc *MockKms) {
	mockSvc = &MockKms{}
	for _, f := range svcKmsSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockKmsSvcAllError builds and returns a MockKms struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockKmsSvcAllError() (mockSvc *MockKms) {
	mockSvc = &MockKms{}
	for _, f := range svcKmsSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockKms) ListKeysPages(
	in *kms.ListKeysInput,
	paginationFunction func(*kms.ListKeysOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListKeysOutput, true)
	return args.Error(0)
}

func (m *MockKms) GetKeyRotationStatus(in *kms.GetKeyRotationStatusInput) (*kms.GetKeyRotationStatusOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*kms.GetKeyRotationStatusOutput), args.Error(1)
}

func (m *MockKms) DescribeKey(in *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*kms.DescribeKeyOutput), args.Error(1)
}

func (m *MockKms) GetKeyPolicy(in *kms.GetKeyPolicyInput) (*kms.GetKeyPolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*kms.GetKeyPolicyOutput), args.Error(1)
}

func (m *MockKms) ListResourceTags(in *kms.ListResourceTagsInput) (*kms.ListResourceTagsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*kms.ListResourceTagsOutput), args.Error(1)
}
