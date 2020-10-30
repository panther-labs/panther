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
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"github.com/stretchr/testify/mock"
)

var (

	//
	// Example configservice variables
	//

	ExampleDescribeConfigurationRecorders = &configservice.DescribeConfigurationRecordersOutput{
		ConfigurationRecorders: []*configservice.ConfigurationRecorder{
			{
				Name: aws.String("default"),
				RecordingGroup: &configservice.RecordingGroup{
					AllSupported:               aws.Bool(true),
					IncludeGlobalResourceTypes: aws.Bool(true),
				},
				RoleARN: aws.String("arn:aws:iam::111111111111:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"),
			},
		},
	}

	ExampleDescribeConfigurationRecorderStatus = &configservice.DescribeConfigurationRecorderStatusOutput{
		ConfigurationRecordersStatus: []*configservice.ConfigurationRecorderStatus{
			{
				LastStartTime:        &ExampleTime,
				LastStatus:           aws.String("SUCCESS"),
				LastStatusChangeTime: &ExampleTime,
				LastStopTime:         &ExampleTime,
				Name:                 aws.String("default"),
				Recording:            aws.Bool(true),
			},
		},
	}

	ExampleConfigName = aws.String("IAmTheConfig")

	svcConfigSetupCalls = map[string]func(*MockConfigService){
		"DescribeConfigurationRecorders": func(svc *MockConfigService) {
			svc.On("DescribeConfigurationRecorders", mock.Anything).
				Return(ExampleDescribeConfigurationRecorders, nil)
		},
		"DescribeConfigurationRecorderStatus": func(svc *MockConfigService) {
			svc.On("DescribeConfigurationRecorderStatus", mock.Anything).
				Return(ExampleDescribeConfigurationRecorderStatus, nil)
		},
	}

	svcConfigSetupCallsError = map[string]func(*MockConfigService){
		"DescribeConfigurationRecorders": func(svc *MockConfigService) {
			svc.On("DescribeConfigurationRecorders", mock.Anything).
				Return(
					&configservice.DescribeConfigurationRecordersOutput{},
					errors.New("fake ConfigService.DescribeRecorders error"),
				)
		},
		"DescribeConfigurationRecorderStatus": func(svc *MockConfigService) {
			svc.On("DescribeConfigurationRecorderStatus", mock.Anything).
				Return(
					&configservice.DescribeConfigurationRecorderStatusOutput{},
					errors.New("fake ConfigService.DescribeStatus error"),
				)
		},
	}

	MockConfigServiceForSetup = &MockConfigService{}
)

// SetupMockConfigService is used to override the ConfigService client initializer
func SetupMockConfigService(_ *session.Session, _ *aws.Config) interface{} {
	return MockConfigServiceForSetup
}

type MockConfigService struct {
	configserviceiface.ConfigServiceAPI
	mock.Mock
}

// BuildMockConfigServiceSvc builds and returns a MockConfigService struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockConfigServiceSvc(funcs []string) (mockSvc *MockConfigService) {
	mockSvc = &MockConfigService{}
	for _, f := range funcs {
		svcConfigSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockConfigServiceSvcError builds and returns a MockConfigService struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockConfigServiceSvcError(funcs []string) (mockSvc *MockConfigService) {
	mockSvc = &MockConfigService{}
	for _, f := range funcs {
		svcConfigSetupCallsError[f](mockSvc)
	}
	return
}

// BuildMockConfigServiceSvcAll builds and returns a MockConfigService struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockConfigServiceSvcAll() (mockSvc *MockConfigService) {
	mockSvc = &MockConfigService{}
	for _, f := range svcConfigSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockConfigServiceSvcAllError builds and returns a MockConfigService struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockConfigServiceSvcAllError() (mockSvc *MockConfigService) {
	mockSvc = &MockConfigService{}
	for _, f := range svcConfigSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockConfigService) DescribeConfigurationRecorders(
	in *configservice.DescribeConfigurationRecordersInput) (*configservice.DescribeConfigurationRecordersOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*configservice.DescribeConfigurationRecordersOutput), args.Error(1)
}

func (m *MockConfigService) DescribeConfigurationRecorderStatus(
	in *configservice.DescribeConfigurationRecorderStatusInput) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*configservice.DescribeConfigurationRecorderStatusOutput), args.Error(1)
}
