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
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/stretchr/testify/mock"
)

// Example Lambda API return values
var (
	ExampleFunctionName = aws.String("example-function-name")

	ExampleFunctionConfiguration = &lambda.FunctionConfiguration{
		FunctionName: aws.String("ExampleFunction"),
		FunctionArn:  aws.String("arn:aws:lambda:us-west-2:123456789012:function:ExampleFunction"),
		Runtime:      aws.String("python3.7"),
		Role:         aws.String("arn:aws:iam::123456789012:role/service-role/ExampleFunction-role-abcdefg"),
		Handler:      aws.String("lambda_function.lambda_handler"),
		CodeSize:     aws.Int64(500),
		Description:  aws.String("This is an example Lambda function"),
		Timeout:      aws.Int64(3),
		MemorySize:   aws.Int64(128),
		LastModified: aws.String("2019-01-01T00:00:00.000+0000"),
		CodeSha256:   aws.String("abcdefghjikl/asdfasdfasdf="),
		Version:      aws.String("$LATEST"),
		TracingConfig: &lambda.TracingConfigResponse{
			Mode: aws.String("PassThrough"),
		},
		RevisionId: aws.String("abcdefg-1234-1234-abcde-1234567890"),
	}

	ExampleListFunctions = &lambda.ListFunctionsOutput{
		Functions: []*lambda.FunctionConfiguration{
			ExampleFunctionConfiguration,
		},
	}

	ExampleListFunctionsContinue = &lambda.ListFunctionsOutput{
		Functions: []*lambda.FunctionConfiguration{
			ExampleFunctionConfiguration,
			ExampleFunctionConfiguration,
		},
		NextMarker: aws.String("1"),
	}

	ExampleListTagsLambda = &lambda.ListTagsOutput{
		Tags: map[string]*string{
			"Application":                   aws.String("Panther"),
			"aws:cloudformation:logical-id": aws.String("LambdaFunction"),
			"aws:cloudformation:stack-id":   aws.String("arn:aws:cloudformation:us-west-2:123456789012:stack/example-function/1234abcdef"),
			"lambda:createdBy":              aws.String("SAM"),
		},
	}

	ExampleGetPolicy = &lambda.GetPolicyOutput{
		Policy:     aws.String("{\"Policy\": \"{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"sns\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:us-west-2:123456789012:function:ExampleFunction\"}]}"),
		RevisionId: aws.String("abcdefg-1234567890-abcdefg"),
	}

	svcLambdaSetupCalls = map[string]func(*MockLambda){
		"ListFunctionsPages": func(svc *MockLambda) {
			svc.On("ListFunctionsPages", mock.Anything).
				Return(nil)
		},
		"ListTags": func(svc *MockLambda) {
			svc.On("ListTags", mock.Anything).
				Return(ExampleListTagsLambda, nil)
		},
		"GetPolicy": func(svc *MockLambda) {
			svc.On("GetPolicy", mock.Anything).
				Return(ExampleGetPolicy, nil)
		},
	}

	svcLambdaSetupCallsError = map[string]func(*MockLambda){
		"ListFunctionsPages": func(svc *MockLambda) {
			svc.On("ListFunctionsPages", mock.Anything).
				Return(errors.New("Lambda.ListFunctionsPages error"))
		},
		"ListTags": func(svc *MockLambda) {
			svc.On("ListTags", mock.Anything).
				Return(&lambda.ListTagsOutput{},
					errors.New("Lambda.ListTags error"),
				)
		},
		"GetPolicy": func(svc *MockLambda) {
			svc.On("GetPolicy", mock.Anything).
				Return(&lambda.GetPolicyOutput{},
					errors.New("Lambda.GetPolicy error"),
				)
		},
	}

	MockLambdaForSetup = &MockLambda{}
)

// Lambda mock

// SetupMockLambda is used to override the Lambda Client initializer
func SetupMockLambda(_ *session.Session, _ *aws.Config) interface{} {
	return MockLambdaForSetup
}

// MockLambda is a mock Lambda client
type MockLambda struct {
	lambdaiface.LambdaAPI
	mock.Mock
}

// BuildMockLambdaSvc builds and returns a MockLambda struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockLambdaSvc(funcs []string) (mockSvc *MockLambda) {
	mockSvc = &MockLambda{}
	for _, f := range funcs {
		svcLambdaSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockLambdaSvcError builds and returns a MockLambda struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockLambdaSvcError(funcs []string) (mockSvc *MockLambda) {
	mockSvc = &MockLambda{}
	for _, f := range funcs {
		svcLambdaSetupCallsError[f](mockSvc)
	}
	return
}

// BuildLambdaServiceSvcAll builds and returns a MockLambda struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockLambdaSvcAll() (mockSvc *MockLambda) {
	mockSvc = &MockLambda{}
	for _, f := range svcLambdaSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockLambdaSvcAllError builds and returns a MockLambda struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockLambdaSvcAllError() (mockSvc *MockLambda) {
	mockSvc = &MockLambda{}
	for _, f := range svcLambdaSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockLambda) ListFunctionsPages(
	in *lambda.ListFunctionsInput,
	paginationFunction func(*lambda.ListFunctionsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListFunctions, true)
	return args.Error(0)
}

func (m *MockLambda) ListTags(in *lambda.ListTagsInput) (*lambda.ListTagsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*lambda.ListTagsOutput), args.Error(1)
}

func (m *MockLambda) GetPolicy(in *lambda.GetPolicyInput) (*lambda.GetPolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*lambda.GetPolicyOutput), args.Error(1)
}
