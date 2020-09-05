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
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/stretchr/testify/mock"
)

// Example ACM API return values
var (
	ExampleDescribeLogGroups = &cloudwatchlogs.DescribeLogGroupsOutput{
		LogGroups: []*cloudwatchlogs.LogGroup{
			{
				LogGroupName:      aws.String("LogGroup-1"),
				CreationTime:      aws.Int64(1234567890123),
				RetentionInDays:   aws.Int64(30),
				MetricFilterCount: aws.Int64(0),
				Arn:               aws.String("arn:aws:logs:us-west-2:123456789012:log-group:LogGroup-1:*"),
				StoredBytes:       aws.Int64(10000000),
			},
			{
				LogGroupName:      aws.String("LogGroup-2"),
				CreationTime:      aws.Int64(1234567890123),
				MetricFilterCount: aws.Int64(0),
				Arn:               aws.String("arn:aws:logs:us-west-2:1234456789012:log-group:LogGroup-2:*"),
				StoredBytes:       aws.Int64(0),
			},
		},
	}

	ExampleDescribeLogGroupsContinue = &cloudwatchlogs.DescribeLogGroupsOutput{
		LogGroups: ExampleDescribeLogGroups.LogGroups,
		NextToken: aws.String("1"),
	}

	ExampleListTagsLogGroup = &cloudwatchlogs.ListTagsLogGroupOutput{
		Tags: map[string]*string{
			"Key1Name": aws.String("Value1"),
		},
	}

	svcCloudWatchLogsSetupCalls = map[string]func(*MockCloudWatchLogs){
		"DescribeLogGroupsPages": func(svc *MockCloudWatchLogs) {
			svc.On("DescribeLogGroupsPages", mock.Anything).
				Return(nil)
		},
		"ListTagsLogGroup": func(svc *MockCloudWatchLogs) {
			svc.On("ListTagsLogGroup", mock.Anything).
				Return(ExampleListTagsLogGroup, nil)
		},
	}

	svcCloudWatchLogsSetupCallsError = map[string]func(*MockCloudWatchLogs){
		"DescribeLogGroupsPages": func(svc *MockCloudWatchLogs) {
			svc.On("DescribeLogGroupsPages", mock.Anything).
				Return(errors.New("CloudWatchLogs.DescribeLogGroupsPages error"))
		},
		"ListTagsLogGroup": func(svc *MockCloudWatchLogs) {
			svc.On("ListTagsLogGroup", mock.Anything).
				Return(&cloudwatchlogs.ListTagsLogGroupOutput{},
					errors.New("CloudWatchLogs.ListTagsLogGroup error"))
		},
	}

	MockCloudWatchLogsForSetup = &MockCloudWatchLogs{}
)

// CloudWatchLogs mock

// SetupMockCloudWatchLogs is used to override the CloudWatchLogs Client initializer
func SetupMockCloudWatchLogs(_ *session.Session, _ *aws.Config) interface{} {
	return MockCloudWatchLogsForSetup
}

// MockCloudWatchLogs is a mock CloudWatchLogs client
type MockCloudWatchLogs struct {
	cloudwatchlogsiface.CloudWatchLogsAPI
	mock.Mock
}

// BuildMockCloudWatchLogsSvc builds and returns a MockCloudWatchLogs struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockCloudWatchLogsSvc(funcs []string) (mockSvc *MockCloudWatchLogs) {
	mockSvc = &MockCloudWatchLogs{}
	for _, f := range funcs {
		svcCloudWatchLogsSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockCloudWatchLogsSvcError builds and returns a MockCloudWatchLogs struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockCloudWatchLogsSvcError(funcs []string) (mockSvc *MockCloudWatchLogs) {
	mockSvc = &MockCloudWatchLogs{}
	for _, f := range funcs {
		svcCloudWatchLogsSetupCallsError[f](mockSvc)
	}
	return
}

// BuildCloudWatchLogsServiceSvcAll builds and returns a MockCloudWatchLogs struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockCloudWatchLogsSvcAll() (mockSvc *MockCloudWatchLogs) {
	mockSvc = &MockCloudWatchLogs{}
	for _, f := range svcCloudWatchLogsSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockCloudWatchLogsSvcAllError builds and returns a MockCloudWatchLogs struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockCloudWatchLogsSvcAllError() (mockSvc *MockCloudWatchLogs) {
	mockSvc = &MockCloudWatchLogs{}
	for _, f := range svcCloudWatchLogsSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockCloudWatchLogs) DescribeLogGroupsPages(
	in *cloudwatchlogs.DescribeLogGroupsInput,
	paginationFunction func(*cloudwatchlogs.DescribeLogGroupsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeLogGroups, true)
	return args.Error(0)
}

func (m *MockCloudWatchLogs) ListTagsLogGroup(in *cloudwatchlogs.ListTagsLogGroupInput) (out *cloudwatchlogs.ListTagsLogGroupOutput, err error) {
	args := m.Called(in)
	return args.Get(0).(*cloudwatchlogs.ListTagsLogGroupOutput), args.Error(1)
}
