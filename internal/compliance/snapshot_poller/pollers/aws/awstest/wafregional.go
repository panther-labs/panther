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
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/aws/aws-sdk-go/service/wafregional"
	"github.com/aws/aws-sdk-go/service/wafregional/wafregionaliface"
	"github.com/stretchr/testify/mock"
)

// Example WAF regional API return values
var (
	ExampleWebAclID = aws.String("asdfasdf-f123-e123-g123-1234asdf1234")

	ExampleGetWebAclForResourceOutput = &wafregional.GetWebACLForResourceOutput{
		WebACLSummary: &waf.WebACLSummary{
			Name:     aws.String("example-web-acl-1"),
			WebACLId: ExampleWebAclID,
		},
	}

	svcWafRegionalSetupCalls = map[string]func(*MockWafRegional){
		"ListWebACLs": func(svc *MockWafRegional) {
			PaginateListWebAcls = false
			svc.On("ListWebACLs", mock.Anything).
				Return(ExampleListWebAclsOutput, nil)
		},
		"GetWebACL": func(svc *MockWafRegional) {
			svc.On("GetWebACL", mock.Anything).
				Return(ExampleGetWebAclOutput, nil)
		},
		"GetWebACLForResource": func(svc *MockWafRegional) {
			svc.On("GetWebACLForResource", mock.Anything).
				Return(ExampleGetWebAclForResourceOutput, nil)
		},
		"ListTagsForResource": func(svc *MockWafRegional) {
			svc.On("ListTagsForResource", mock.Anything).
				Return(ExampleListTagsForResourceWaf, nil)
		},
		"GetRule": func(svc *MockWafRegional) {
			svc.On("GetRule", mock.Anything).
				Return(ExampleGetRule, nil)
		},
	}

	svcWafRegionalSetupCallsError = map[string]func(*MockWafRegional){
		"ListWebACLs": func(svc *MockWafRegional) {
			svc.On("ListWebACLs", mock.Anything).
				Return(
					&waf.ListWebACLsOutput{},
					errors.New("WAF.ListWebACLs"),
				)
		},
		"GetWebACL": func(svc *MockWafRegional) {
			svc.On("GetWebACL", mock.Anything).
				Return(&waf.GetWebACLOutput{},
					errors.New("WAF.GetWebACL error"),
				)
		},
		"GetWebACLForResource": func(svc *MockWafRegional) {
			svc.On("GetWebACLForResource", mock.Anything).
				Return(&wafregional.GetWebACLForResourceOutput{},
					errors.New("WAF.Regional.GetWebACLForResource error"),
				)
		},
		"ListTagsForResource": func(svc *MockWafRegional) {
			svc.On("ListTagsForResource", mock.Anything).
				Return(&waf.ListTagsForResourceOutput{},
					errors.New("WAF.Regional.ListTagsForResource error"),
				)
		},
		"GetRule": func(svc *MockWafRegional) {
			svc.On("GetRule", mock.Anything).
				Return(&waf.GetRuleOutput{},
					errors.New("WAF.Regional.GetRule error"),
				)
		},
	}

	MockWafRegionalForSetup = &MockWafRegional{}
)

// WAF Regional mock

// SetupMockWafRegional is used to override the WAF Regional Client initializer
func SetupMockWafRegional(_ *session.Session, _ *aws.Config) interface{} {
	return MockWafRegionalForSetup
}

// MockWafRegional is a mock WAF regional client
type MockWafRegional struct {
	wafregionaliface.WAFRegionalAPI
	mock.Mock
}

// BuildMockWafRegionalSvc builds and returns a MockWafRegional struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockWafRegionalSvc(funcs []string) (mockSvc *MockWafRegional) {
	mockSvc = &MockWafRegional{}
	for _, f := range funcs {
		svcWafRegionalSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockWafRegionalSvcError builds and returns a MockWafRegional struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockWafRegionalSvcError(funcs []string) (mockSvc *MockWafRegional) {
	mockSvc = &MockWafRegional{}
	for _, f := range funcs {
		svcWafRegionalSetupCallsError[f](mockSvc)
	}
	return
}

// BuildWafRegionalServiceSvcAll builds and returns a MockWafRegional struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockWafRegionalSvcAll() (mockSvc *MockWafRegional) {
	mockSvc = &MockWafRegional{}
	for _, f := range svcWafRegionalSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockWafRegionalSvcAllError builds and returns a MockWafRegional struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockWafRegionalSvcAllError() (mockSvc *MockWafRegional) {
	mockSvc = &MockWafRegional{}
	for _, f := range svcWafRegionalSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockWafRegional) ListWebACLs(in *waf.ListWebACLsInput) (*waf.ListWebACLsOutput, error) {
	PaginateListWebAcls = !PaginateListWebAcls
	args := m.Called(in)
	if PaginateListWebAcls {
		return args.Get(0).(*waf.ListWebACLsOutput), args.Error(1)
	}
	var empty []*waf.WebACLSummary
	return &waf.ListWebACLsOutput{WebACLs: empty}, args.Error(1)
}

func (m *MockWafRegional) GetWebACL(in *waf.GetWebACLInput) (*waf.GetWebACLOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*waf.GetWebACLOutput), args.Error(1)
}

func (m *MockWafRegional) GetWebACLForResource(in *wafregional.GetWebACLForResourceInput) (*wafregional.GetWebACLForResourceOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*wafregional.GetWebACLForResourceOutput), args.Error(1)
}

func (m *MockWafRegional) ListTagsForResource(in *waf.ListTagsForResourceInput) (*waf.ListTagsForResourceOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*waf.ListTagsForResourceOutput), args.Error(1)
}

func (m *MockWafRegional) GetRule(in *waf.GetRuleInput) (*waf.GetRuleOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*waf.GetRuleOutput), args.Error(1)
}
