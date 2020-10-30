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
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling/applicationautoscalingiface"
	"github.com/stretchr/testify/mock"
)

// Example ApplicationAutoScaling return values
var (
	ExampleDescribeScalableTargetsOutput = &applicationautoscaling.DescribeScalableTargetsOutput{
		ScalableTargets: []*applicationautoscaling.ScalableTarget{
			{
				ServiceNamespace:  aws.String("dynamodb"),
				ResourceId:        aws.String("table/example-table"),
				ScalableDimension: aws.String("dynamodb:table:ReadCapacityUnits"),
				MinCapacity:       aws.Int64(5),
				MaxCapacity:       aws.Int64(4000),
				RoleARN:           aws.String("arn:aws:iam::123456789012:role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/AutoScalingRole"),
				CreationTime:      &ExampleTime,
			},
			{
				ServiceNamespace:  aws.String("dynamodb"),
				ResourceId:        aws.String("table/example-table"),
				ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
				MinCapacity:       aws.Int64(5),
				MaxCapacity:       aws.Int64(40000),
				RoleARN:           aws.String("arn:aws:iam::123456789012:role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/AutoScalingRole"),
				CreationTime:      &ExampleTime,
			},
		},
	}

	svcApplicationAutoScalingSetupCalls = map[string]func(*MockApplicationAutoScaling){
		"DescribeScalableTargetsPages": func(svc *MockApplicationAutoScaling) {
			svc.On("DescribeScalableTargetsPages", mock.Anything).
				Return(nil)
		},
	}

	svcApplicationAutoScalingSetupCallsError = map[string]func(*MockApplicationAutoScaling){
		"DescribeScalableTargetsPages": func(svc *MockApplicationAutoScaling) {
			svc.On("DescribeScalableTargetsPages", mock.Anything).
				Return(errors.New("ApplicationAutoScaling.DescribeScalableTargetsPages"))
		},
	}

	MockApplicationAutoScalingForSetup = &MockApplicationAutoScaling{}
)

// Application Auto Scaling mock

// SetupMockApplicationAutoScaling is used to override the Application Auto Scaling Client initializer
func SetupMockApplicationAutoScaling(sess *session.Session, cfg *aws.Config) interface{} {
	return MockApplicationAutoScalingForSetup
}

// MockApplicationAutoScaling is a mock Application Auto Scaling client
type MockApplicationAutoScaling struct {
	applicationautoscalingiface.ApplicationAutoScalingAPI
	mock.Mock
}

// BuildMockApplicationAutoScalingSvc builds and returns a MockApplicationAutoScaling struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockApplicationAutoScalingSvc(funcs []string) (mockSvc *MockApplicationAutoScaling) {
	mockSvc = &MockApplicationAutoScaling{}
	for _, f := range funcs {
		svcApplicationAutoScalingSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockApplicationAutoScalingSvcError builds and returns a MockApplicationAutoScaling struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockApplicationAutoScalingSvcError(funcs []string) (mockSvc *MockApplicationAutoScaling) {
	mockSvc = &MockApplicationAutoScaling{}
	for _, f := range funcs {
		svcApplicationAutoScalingSetupCallsError[f](mockSvc)
	}
	return
}

// BuildApplicationAutoScalingServiceSvcAll builds and returns a MockApplicationAutoScaling struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockApplicationAutoScalingSvcAll() (mockSvc *MockApplicationAutoScaling) {
	mockSvc = &MockApplicationAutoScaling{}
	for _, f := range svcApplicationAutoScalingSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockApplicationAutoScalingSvcAllError builds and returns a MockApplicationAutoScaling struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockApplicationAutoScalingSvcAllError() (mockSvc *MockApplicationAutoScaling) {
	mockSvc = &MockApplicationAutoScaling{}
	for _, f := range svcApplicationAutoScalingSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockApplicationAutoScaling) DescribeScalableTargetsPages(
	in *applicationautoscaling.DescribeScalableTargetsInput,
	paginationFunction func(*applicationautoscaling.DescribeScalableTargetsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeScalableTargetsOutput, true)
	return args.Error(0)
}
