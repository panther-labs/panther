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
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/acm/acmiface"
	"github.com/stretchr/testify/mock"
)

// Example ACM API return values
var (
	ExampleCertificateArn = aws.String("arn:aws:acm:us-west-2:123456789012:certificate/asdfasdf-1234-1234-1234-1")

	ExampleListCertificatesOutput = &acm.ListCertificatesOutput{
		CertificateSummaryList: []*acm.CertificateSummary{
			{
				DomainName:     aws.String("runpanther.xyz"),
				CertificateArn: ExampleCertificateArn,
			},
		},
	}

	ExampleListCertificatesOutputContinue = &acm.ListCertificatesOutput{
		CertificateSummaryList: []*acm.CertificateSummary{
			{
				DomainName:     aws.String("runpanther.123"),
				CertificateArn: ExampleCertificateArn,
			},
			{
				DomainName:     aws.String("runpanther.abc"),
				CertificateArn: ExampleCertificateArn,
			},
		},
		NextToken: aws.String("1"),
	}

	ExampleDescribeCertificateOutput = &acm.DescribeCertificateOutput{
		Certificate: &acm.CertificateDetail{
			CertificateArn:     ExampleCertificateArn,
			CreatedAt:          &ExampleTime,
			DomainName:         aws.String("runpanther.xyz"),
			Serial:             aws.String("b7:5b:09:63:dd:47:9c:46"),
			NotBefore:          &ExampleTime,
			NotAfter:           &ExampleTime,
			KeyAlgorithm:       aws.String("RSA-2048"),
			SignatureAlgorithm: aws.String("SHA256WITHRSA"),
			Type:               aws.String("AMAZON_CREATED"),
		},
	}

	ExampleListTagsForCertificate = &acm.ListTagsForCertificateOutput{
		Tags: []*acm.Tag{
			{
				Key:   aws.String("Key1"),
				Value: aws.String("Value1"),
			},
		},
	}

	svcAcmSetupCalls = map[string]func(*MockAcm){
		"ListCertificatesPages": func(svc *MockAcm) {
			svc.On("ListCertificatesPages", mock.Anything).
				Return(nil)
		},
		"DescribeCertificate": func(svc *MockAcm) {
			svc.On("DescribeCertificate", mock.Anything).
				Return(ExampleDescribeCertificateOutput, nil)
		},
		"ListTagsForCertificate": func(svc *MockAcm) {
			svc.On("ListTagsForCertificate", mock.Anything).
				Return(ExampleListTagsForCertificate, nil)
		},
	}

	svcAcmSetupCallsError = map[string]func(*MockAcm){
		"ListCertificatesPages": func(svc *MockAcm) {
			svc.On("ListCertificatesPages", mock.Anything).
				Return(errors.New("ACM.ListCertificatesPages error"))
		},
		"DescribeCertificate": func(svc *MockAcm) {
			svc.On("DescribeCertificate", mock.Anything).
				Return(&acm.DescribeCertificateOutput{},
					errors.New("ACM.DescribeCertificate error"),
				)
		},
		"ListTagsForCertificate": func(svc *MockAcm) {
			svc.On("ListTagsForCertificate", mock.Anything).
				Return(&acm.ListTagsForCertificateOutput{},
					errors.New("ACM.ListTagsForCertificate error"),
				)
		},
	}

	MockAcmForSetup = &MockAcm{}
)

// ACM mock

// SetupMockAcm is used to override the ACM Client initializer
func SetupMockAcm(_ *session.Session, _ *aws.Config) interface{} {
	return MockAcmForSetup
}

// MockAcm is a mock ACM client
type MockAcm struct {
	acmiface.ACMAPI
	mock.Mock
}

// BuildMockAcmSvc builds and returns a MockAcm struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockAcmSvc(funcs []string) (mockSvc *MockAcm) {
	mockSvc = &MockAcm{}
	for _, f := range funcs {
		svcAcmSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockAcmSvcError builds and returns a MockAcm struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockAcmSvcError(funcs []string) (mockSvc *MockAcm) {
	mockSvc = &MockAcm{}
	for _, f := range funcs {
		svcAcmSetupCallsError[f](mockSvc)
	}
	return
}

// BuildAcmServiceSvcAll builds and returns a MockAcm struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockAcmSvcAll() (mockSvc *MockAcm) {
	mockSvc = &MockAcm{}
	for _, f := range svcAcmSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockAcmSvcAllError builds and returns a MockAcm struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockAcmSvcAllError() (mockSvc *MockAcm) {
	mockSvc = &MockAcm{}
	for _, f := range svcAcmSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockAcm) ListCertificatesPages(
	in *acm.ListCertificatesInput,
	paginationFunction func(*acm.ListCertificatesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListCertificatesOutput, true)
	return args.Error(0)
}

func (m *MockAcm) DescribeCertificate(in *acm.DescribeCertificateInput) (*acm.DescribeCertificateOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*acm.DescribeCertificateOutput), args.Error(1)
}

func (m *MockAcm) ListTagsForCertificate(in *acm.ListTagsForCertificateInput) (*acm.ListTagsForCertificateOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*acm.ListTagsForCertificateOutput), args.Error(1)
}
