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
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/guardduty/guarddutyiface"
	"github.com/stretchr/testify/mock"
)

// Example GuardDuty API return values
var (
	ExampleDetectorID = aws.String("12a12345b12345c12ab12a1a1ab1a1ab1")

	ExampleListDetectorsOutput = &guardduty.ListDetectorsOutput{
		DetectorIds: []*string{
			ExampleDetectorID,
		},
	}

	ExampleGetMasterAccountOutput = &guardduty.GetMasterAccountOutput{
		Master: &guardduty.Master{
			AccountId:          aws.String("99a12345b12345c12ab12a1a1ab1a1ab1"),
			InvitationId:       aws.String("11111111111111"),
			InvitedAt:          aws.String("2019"),
			RelationshipStatus: aws.String("active"),
		},
	}

	ExampleGetDetector = &guardduty.GetDetectorOutput{
		CreatedAt:                  aws.String("2019-01-01T00:00:00.000Z"),
		FindingPublishingFrequency: aws.String("SIX_HOURS"),
		ServiceRole:                aws.String("arn:aws:iam::123456789012:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"),
		Status:                     aws.String("ENABLED"),
		UpdatedAt:                  aws.String("2019-01-01T00:00:00.000Z"),
		Tags: map[string]*string{
			"KeyName1": aws.String("Value1"),
		},
	}

	svcGuardDutySetupCalls = map[string]func(*MockGuardDuty){
		"ListDetectorsPages": func(svc *MockGuardDuty) {
			svc.On("ListDetectorsPages", mock.Anything).
				Return(nil)
		},
		"GetMasterAccount": func(svc *MockGuardDuty) {
			svc.On("GetMasterAccount", mock.Anything).
				Return(ExampleGetMasterAccountOutput, nil)
		},
		"GetDetector": func(svc *MockGuardDuty) {
			svc.On("GetDetector", mock.Anything).
				Return(ExampleGetDetector, nil)
		},
	}

	svcGuardDutySetupCallsError = map[string]func(*MockGuardDuty){
		"ListDetectorsPages": func(svc *MockGuardDuty) {
			svc.On("ListDetectorsPages", mock.Anything).
				Return(errors.New("GuardDuty.ListDetectorsPages error"))
		},
		"GetMasterAccount": func(svc *MockGuardDuty) {
			svc.On("GetMasterAccount", mock.Anything).
				Return(&guardduty.GetMasterAccountOutput{},
					errors.New("GuardDuty.GetMasterAccount error"),
				)
		},
		"GetDetector": func(svc *MockGuardDuty) {
			svc.On("GetDetector", mock.Anything).
				Return(&guardduty.GetDetectorOutput{},
					errors.New("GuardDuty.GetDetector error"),
				)
		},
	}

	MockGuardDutyForSetup = &MockGuardDuty{}
)

// GuardDuty mock

// SetupMockGuardDuty is used to override the GuardDuty Client initializer
func SetupMockGuardDuty(_ *session.Session, _ *aws.Config) interface{} {
	return MockGuardDutyForSetup
}

// MockGuardDuty is a mock GuardDuty client
type MockGuardDuty struct {
	guarddutyiface.GuardDutyAPI
	mock.Mock
}

// BuildMockGuardDutySvc builds and returns a MockGuardDuty struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockGuardDutySvc(funcs []string) (mockSvc *MockGuardDuty) {
	mockSvc = &MockGuardDuty{}
	for _, f := range funcs {
		svcGuardDutySetupCalls[f](mockSvc)
	}
	return
}

// BuildMockGuardDutySvcError builds and returns a MockGuardDuty struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockGuardDutySvcError(funcs []string) (mockSvc *MockGuardDuty) {
	mockSvc = &MockGuardDuty{}
	for _, f := range funcs {
		svcGuardDutySetupCallsError[f](mockSvc)
	}
	return
}

// BuildGuardDutyServiceSvcAll builds and returns a MockGuardDuty struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockGuardDutySvcAll() (mockSvc *MockGuardDuty) {
	mockSvc = &MockGuardDuty{}
	for _, f := range svcGuardDutySetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockGuardDutySvcAllError builds and returns a MockGuardDuty struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockGuardDutySvcAllError() (mockSvc *MockGuardDuty) {
	mockSvc = &MockGuardDuty{}
	for _, f := range svcGuardDutySetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockGuardDuty) ListDetectors(in *guardduty.ListDetectorsInput) (*guardduty.ListDetectorsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*guardduty.ListDetectorsOutput), args.Error(1)
}

func (m *MockGuardDuty) ListDetectorsPages(
	in *guardduty.ListDetectorsInput,
	paginationFunction func(*guardduty.ListDetectorsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListDetectorsOutput, true)
	return args.Error(0)
}

func (m *MockGuardDuty) GetMasterAccount(in *guardduty.GetMasterAccountInput) (*guardduty.GetMasterAccountOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*guardduty.GetMasterAccountOutput), args.Error(1)
}

func (m *MockGuardDuty) GetDetector(in *guardduty.GetDetectorInput) (*guardduty.GetDetectorOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*guardduty.GetDetectorOutput), args.Error(1)
}
