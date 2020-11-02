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
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudformation/cloudformationiface"
	"github.com/stretchr/testify/mock"
)

// Example CloudFormation API return values
var (
	StackDriftDetectionInProgress = false

	ExampleDescribeStacks = &cloudformation.DescribeStacksOutput{
		Stacks: []*cloudformation.Stack{
			{
				StackId:     aws.String("arn:aws:cloudformation:us-west-2:111111111111:stack/iam-roles/67fc9960-556b-11e9-a978-067794494828"),
				StackName:   aws.String("iam-roles"),
				Description: aws.String("Nick's IAM Admin role"),
				Parameters: []*cloudformation.Parameter{
					{
						ParameterKey:   aws.String("MaxSessionDurationSec"),
						ParameterValue: aws.String("28800"),
					},
					{
						ParameterKey:   aws.String("Prefix"),
						ParameterValue: aws.String("DevNick"),
					},
				},
				CreationTime:    &ExampleTime,
				LastUpdatedTime: &ExampleTime,
				RollbackConfiguration: &cloudformation.RollbackConfiguration{
					RollbackTriggers: []*cloudformation.RollbackTrigger{},
				},
				StackStatus:      aws.String("UPDATE_COMPLETE"),
				DisableRollback:  aws.Bool(false),
				NotificationARNs: []*string{},
				Capabilities: []*string{
					aws.String("CAPABILITY_NAMED_IAM"),
				},
				Tags: []*cloudformation.Tag{},
				DriftInformation: &cloudformation.StackDriftInformation{
					StackDriftStatus:   aws.String("DRIFTED"),
					LastCheckTimestamp: &ExampleTime,
				},
			},
		},
	}
	ExampleDescribeStacksContinue = &cloudformation.DescribeStacksOutput{
		Stacks: []*cloudformation.Stack{
			ExampleDescribeStacks.Stacks[0],
			ExampleDescribeStacks.Stacks[0],
		},
		NextToken: aws.String("1"),
	}

	ExampleDescribeStackResourceDrifts = &cloudformation.DescribeStackResourceDriftsOutput{
		StackResourceDrifts: []*cloudformation.StackResourceDrift{
			{
				StackId:            aws.String("arn:aws:cloudformation:us-west-2:111111111111:stack/iam-roles/67fc9960-556b-11e9-a978-067794494828"),
				LogicalResourceId:  aws.String("Administrators"),
				PhysicalResourceId: aws.String("PantherDevNickAdministrator"),
				ResourceType:       aws.String("AWS::IAM::Role"),
				ExpectedProperties: aws.String("{\"AssumeRolePolicyDocument\":{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Condition\":{\"Bool\":{\"aws:MultiFactorAuthPresent\":true,\"aws:SecureTransport\":true},\"NumericLessThan\":{\"aws:MultiFactorAuthAge\":28800}},\"Effect\":\"Allow\",\"Principal\":{\"AWS\":111111111111}}],\"Version\":\"2012-10-17\"},\"ManagedPolicyArns\":[\"arn:aws:iam::aws:policy/AdministratorAccess\"],\"MaxSessionDuration\":28800,\"RoleName\":\"PantherDevNickAdministrator\"}"),
				ActualProperties:   aws.String("{\"AssumeRolePolicyDocument\":{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Condition\":{\"Bool\":{\"aws:MultiFactorAuthPresent\":true,\"aws:SecureTransport\":true},\"NumericLessThan\":{\"aws:MultiFactorAuthAge\":28800}},\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111111111111:root\"}}],\"Version\":\"2012-10-17\"},\"ManagedPolicyArns\":[\"arn:aws:iam::aws:policy/AdministratorAccess\"],\"MaxSessionDuration\":28800,\"RoleName\":\"PantherDevNickAdministrator\"}"),
				PropertyDifferences: []*cloudformation.PropertyDifference{
					{
						PropertyPath:   aws.String("/AssumeRolePolicyDocument/Statement/0/Principal/AWS"),
						ExpectedValue:  aws.String("111111111111"),
						ActualValue:    aws.String("arn:aws:iam::111111111111:root"),
						DifferenceType: aws.String("NOT_EQUAL"),
					},
				},
				StackResourceDriftStatus: aws.String("MODIFIED"),
				Timestamp:                &ExampleTime,
			},
		},
	}

	ExampleDetectStackDrift = &cloudformation.DetectStackDriftOutput{
		StackDriftDetectionId: aws.String("5115ff60-b863-11e9-bf7f-0657eb5c1e84"),
	}

	ExampleDescribeStackDriftDetectionStatus = &cloudformation.DescribeStackDriftDetectionStatusOutput{
		StackId:                   aws.String("arn:aws:cloudformation:us-west-2:111111111111:stack/iam-roles/67fc9960-556b-11e9-a978-067794494828"),
		StackDriftDetectionId:     aws.String("5115ff60-b863-11e9-bf7f-0657eb5c1e84"),
		StackDriftStatus:          aws.String("DRIFTED"),
		DetectionStatus:           aws.String("DETECTION_COMPLETE"),
		DriftedStackResourceCount: aws.Int64(1),
		Timestamp:                 &ExampleTime,
	}

	ExampleDescribeStackDriftDetectionStatusInProgress = &cloudformation.DescribeStackDriftDetectionStatusOutput{
		StackId:                   aws.String("arn:aws:cloudformation:us-west-2:111111111111:stack/iam-roles/67fc9960-556b-11e9-a978-067794494828"),
		StackDriftDetectionId:     aws.String("5115ff60-b863-11e9-bf7f-0657eb5c1e84"),
		StackDriftStatus:          aws.String("DRIFTED"),
		DetectionStatus:           aws.String("DETECTION_IN_PROGESS"),
		DriftedStackResourceCount: aws.Int64(1),
		Timestamp:                 &ExampleTime,
	}

	svcCloudFormationSetupCalls = map[string]func(*MockCloudFormation){
		"DescribeStacksPages": func(svc *MockCloudFormation) {
			svc.On("DescribeStacksPages", mock.Anything).
				Return(nil)
		},
		"DescribeStackResourceDriftsPages": func(svc *MockCloudFormation) {
			svc.On("DescribeStackResourceDriftsPages", mock.Anything).
				Return(nil)
		},
		"DescribeStacks": func(svc *MockCloudFormation) {
			svc.On("DescribeStacks", mock.Anything).
				Return(ExampleDescribeStacks, nil)
		},
		"DetectStackDrift": func(svc *MockCloudFormation) {
			svc.On("DetectStackDrift", mock.Anything).
				Return(ExampleDetectStackDrift, nil)
		},
		"DescribeStackDriftDetectionStatus": func(svc *MockCloudFormation) {
			svc.On("DescribeStackDriftDetectionStatus", mock.Anything).
				Return(ExampleDescribeStackDriftDetectionStatus, nil)
		},
	}

	svcCloudFormationSetupCallsError = map[string]func(*MockCloudFormation){
		"DescribeStacksPages": func(svc *MockCloudFormation) {
			svc.On("DescribeStacksPages", mock.Anything).
				Return(errors.New("CloudFormation.DescribeStacksPages error"))
		},
		"DescribeStackResourceDriftsPages": func(svc *MockCloudFormation) {
			svc.On("DescribeStackResourceDriftsPages", mock.Anything).
				Return(errors.New("CloudFormation.DescribeStackResourceDriftsPages error"))
		},
		"DescribeStacks": func(svc *MockCloudFormation) {
			svc.On("DescribeStacks", mock.Anything).
				Return(&cloudformation.DescribeStacksOutput{}, errors.New("CloudFormation.DescribeStacks error"))
		},
		"DetectStackDrift": func(svc *MockCloudFormation) {
			svc.On("DetectStackDrift", mock.Anything).
				Return(&cloudformation.DetectStackDriftOutput{},
					errors.New("CloudFormation.DetectStackDrift error"),
				)
		},
		"DescribeStackDriftDetectionStatus": func(svc *MockCloudFormation) {
			svc.On("DescribeStackDriftDetectionStatus", mock.Anything).
				Return(&cloudformation.DescribeStackDriftDetectionStatusOutput{},
					errors.New("CloudFormation.DescribeStackDriftDetectionStatus error"),
				)
		},
	}

	MockCloudFormationForSetup = &MockCloudFormation{}
)

// CloudFormation mock

// SetupMockCloudFormation is used to override the CloudFormation Client initializer
func SetupMockCloudFormation(_ *session.Session, _ *aws.Config) interface{} {
	return MockCloudFormationForSetup
}

// MockCloudFormation is a mock CloudFormation client
type MockCloudFormation struct {
	cloudformationiface.CloudFormationAPI
	mock.Mock
}

// BuildMockCloudFormationSvc builds and returns a MockCloudFormation struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockCloudFormationSvc(funcs []string) (mockSvc *MockCloudFormation) {
	mockSvc = &MockCloudFormation{}
	for _, f := range funcs {
		svcCloudFormationSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockCloudFormationSvcError builds and returns a MockCloudFormation struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockCloudFormationSvcError(funcs []string) (mockSvc *MockCloudFormation) {
	mockSvc = &MockCloudFormation{}
	for _, f := range funcs {
		svcCloudFormationSetupCallsError[f](mockSvc)
	}
	return
}

// BuildCloudFormationServiceSvcAll builds and returns a MockCloudFormation struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockCloudFormationSvcAll() (mockSvc *MockCloudFormation) {
	mockSvc = &MockCloudFormation{}
	for _, f := range svcCloudFormationSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockCloudFormationSvcAllError builds and returns a MockCloudFormation struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockCloudFormationSvcAllError() (mockSvc *MockCloudFormation) {
	mockSvc = &MockCloudFormation{}
	for _, f := range svcCloudFormationSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockCloudFormation) DescribeStacksPages(
	in *cloudformation.DescribeStacksInput,
	paginationFunction func(*cloudformation.DescribeStacksOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeStacks, true)
	return args.Error(0)
}

func (m *MockCloudFormation) DescribeStackResourceDriftsPages(
	in *cloudformation.DescribeStackResourceDriftsInput,
	paginationFunction func(*cloudformation.DescribeStackResourceDriftsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeStackResourceDrifts, true)
	return args.Error(0)
}

func (m *MockCloudFormation) DescribeStacks(in *cloudformation.DescribeStacksInput) (*cloudformation.DescribeStacksOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*cloudformation.DescribeStacksOutput), args.Error(1)
}

func (m *MockCloudFormation) DetectStackDrift(in *cloudformation.DetectStackDriftInput) (*cloudformation.DetectStackDriftOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*cloudformation.DetectStackDriftOutput), args.Error(1)
}

func (m *MockCloudFormation) DescribeStackDriftDetectionStatus(
	in *cloudformation.DescribeStackDriftDetectionStatusInput,
) (*cloudformation.DescribeStackDriftDetectionStatusOutput, error) {

	if StackDriftDetectionInProgress {
		StackDriftDetectionInProgress = false
		return ExampleDescribeStackDriftDetectionStatusInProgress, nil
	}

	args := m.Called(in)
	return args.Get(0).(*cloudformation.DescribeStackDriftDetectionStatusOutput), args.Error(1)
}
