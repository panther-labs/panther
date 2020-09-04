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
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/stretchr/testify/mock"
)

var (
	ExampleTrail = &cloudtrail.Trail{
		CloudWatchLogsLogGroupArn:  aws.String("arn:aws:logs:us-west-2:123456789012:log-group:Trail:*"),
		CloudWatchLogsRoleArn:      aws.String("arn:aws:iam::123456789012:role/Trail"),
		HasCustomEventSelectors:    aws.Bool(true),
		HomeRegion:                 aws.String("us-west-2"),
		IncludeGlobalServiceEvents: aws.Bool(true),
		IsMultiRegionTrail:         aws.Bool(true),
		IsOrganizationTrail:        aws.Bool(true),
		KmsKeyId:                   aws.String("arn:aws:kms:us-west-2:123456789012:key/2222dddd-ffff-4444-8888-999911113"),
		LogFileValidationEnabled:   aws.Bool(true),
		Name:                       aws.String("Trail"),
		S3BucketName:               aws.String("unit-test-cloudtrail-bucket"),
		TrailARN:                   aws.String("arn:aws:cloudtrail:us-west-2:123456789012:trail/Trail"),
	}

	ExampleTrailStatus = &cloudtrail.GetTrailStatusOutput{
		IsLogging: aws.Bool(true),
	}

	ExampleTrailEventSelectors = []*cloudtrail.EventSelector{{
		IncludeManagementEvents: aws.Bool(true),
		ReadWriteType:           aws.String("All"),
		DataResources: []*cloudtrail.DataResource{{
			Type: aws.String("AWS::S3::Object"),
		}},
	}}

	ExampleListTagsCloudTrail = &cloudtrail.ListTagsOutput{
		ResourceTagList: []*cloudtrail.ResourceTag{
			{
				TagsList: []*cloudtrail.Tag{
					{
						Key:   aws.String("Key1Name"),
						Value: aws.String("Value1Name"),
					},
					{
						Key:   aws.String("Key2Name"),
						Value: aws.String("Value2Name"),
					},
				},
				ResourceId: ExampleTrail.TrailARN,
			},
		},
	}

	ExampleDescribeTrails = &cloudtrail.DescribeTrailsOutput{
		TrailList: []*cloudtrail.Trail{ExampleTrail},
	}

	ExampleGetEventSelectors = &cloudtrail.GetEventSelectorsOutput{
		EventSelectors: ExampleTrailEventSelectors,
		TrailARN:       ExampleTrail.TrailARN,
	}

	svcCloudTrailSetupCalls = map[string]func(*MockCloudTrail){
		"DescribeTrails": func(svc *MockCloudTrail) {
			svc.On("DescribeTrails", mock.Anything).
				Return(ExampleDescribeTrails, nil)
		},
		"GetTrailStatus": func(svc *MockCloudTrail) {
			svc.On("GetTrailStatus", mock.Anything).
				Return(ExampleTrailStatus, nil)
		},
		"GetEventSelectors": func(svc *MockCloudTrail) {
			svc.On("GetEventSelectors", mock.Anything).
				Return(ExampleGetEventSelectors, nil)
		},
		"ListTags": func(svc *MockCloudTrail) {
			svc.On("ListTags", mock.Anything).
				Return(ExampleListTagsCloudTrail, nil)
		},
	}

	svcCloudTrailSetupCallsError = map[string]func(*MockCloudTrail){
		"DescribeTrails": func(svc *MockCloudTrail) {
			svc.On("DescribeTrails", mock.Anything).
				Return(&cloudtrail.DescribeTrailsOutput{},
					errors.New("CloudTrail.DescribeTrails error"),
				)
		},
		"GetTrailStatus": func(svc *MockCloudTrail) {
			svc.On("GetTrailStatus", mock.Anything).
				Return(&cloudtrail.GetTrailStatusOutput{},
					errors.New("CloudTrail.GetTrailStatus error"),
				)
		},
		"GetEventSelectors": func(svc *MockCloudTrail) {
			svc.On("GetEventSelectors", mock.Anything).
				Return(&cloudtrail.GetEventSelectorsOutput{},
					errors.New("CloudTrail.GetEventSelectors error"),
				)
		},
		"ListTags": func(svc *MockCloudTrail) {
			svc.On("ListTags", mock.Anything).
				Return(&cloudtrail.ListTagsOutput{},
					errors.New("CloudTrail.ListTags error"),
				)
		},
	}

	// MockCloudTrailForSetup is the object returned by the SetupMockCloudTrail function.
	MockCloudTrailForSetup = &MockCloudTrail{}
)

// SetupMockCloudTrail is used to override the CloudTrail client initializer.
func SetupMockCloudTrail(_ *session.Session, _ *aws.Config) interface{} {
	return MockCloudTrailForSetup
}

// MockCloudTrail is a mock CloudTrail client.
type MockCloudTrail struct {
	cloudtrailiface.CloudTrailAPI
	mock.Mock
}

// BuildMockCloudTrailSvc builds and returns a MockCloudTrail struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockCloudTrailSvc(funcs []string) (mockSvc *MockCloudTrail) {
	mockSvc = &MockCloudTrail{}
	for _, f := range funcs {
		svcCloudTrailSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockCloudTrailSvcError builds and returns a MockCloudTrail struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockCloudTrailSvcError(funcs []string) (mockSvc *MockCloudTrail) {
	mockSvc = &MockCloudTrail{}
	for _, f := range funcs {
		svcCloudTrailSetupCallsError[f](mockSvc)
	}
	return
}

// BuildCloudTrailServiceSvcAll builds and returns a MockCloudTrail struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockCloudTrailSvcAll() (mockSvc *MockCloudTrail) {
	mockSvc = &MockCloudTrail{}
	for _, f := range svcCloudTrailSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockCloudTrailSvcAllError builds and returns a MockCloudTrail struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockCloudTrailSvcAllError() (mockSvc *MockCloudTrail) {
	mockSvc = &MockCloudTrail{}
	for _, f := range svcCloudTrailSetupCallsError {
		f(mockSvc)
	}
	return
}

// DescribeTrails is a mock function to return fake CloudTrail data.
func (m *MockCloudTrail) DescribeTrails(
	in *cloudtrail.DescribeTrailsInput,
) (*cloudtrail.DescribeTrailsOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*cloudtrail.DescribeTrailsOutput), args.Error(1)
}

// GetTrailStatus is a mock function to return fake CloudTrail Status data.
func (m *MockCloudTrail) GetTrailStatus(
	in *cloudtrail.GetTrailStatusInput,
) (*cloudtrail.GetTrailStatusOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*cloudtrail.GetTrailStatusOutput), args.Error(1)
}

// GetEventSelectors is a mock function to return fake CloudTrail Event Selector data.
func (m *MockCloudTrail) GetEventSelectors(
	in *cloudtrail.GetEventSelectorsInput,
) (*cloudtrail.GetEventSelectorsOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*cloudtrail.GetEventSelectorsOutput), args.Error(1)
}

func (m *MockCloudTrail) ListTags(
	in *cloudtrail.ListTagsInput,
) (*cloudtrail.ListTagsOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*cloudtrail.ListTagsOutput), args.Error(1)
}
