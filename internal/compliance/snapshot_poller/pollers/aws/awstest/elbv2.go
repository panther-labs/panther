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
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/stretchr/testify/mock"
)

// Example ELBV2 API return values
var (
	ExampleDescribeLoadBalancersOutput = &elbv2.DescribeLoadBalancersOutput{
		LoadBalancers: []*elbv2.LoadBalancer{
			{
				LoadBalancerArn:       aws.String("arn:aws:elasticloadbalancing:us-west-2:111111111111:loadbalancer/app/panther-test/aaaaaaaaaaaaa"),
				DNSName:               aws.String("internal-panther-test-123456789.us-west-2.elb.amazonaws.com"),
				CanonicalHostedZoneId: aws.String("AAAAA123"),
				CreatedTime:           &ExampleTime,
				LoadBalancerName:      aws.String("panther-test"),
				Scheme:                aws.String("internal"),
				VpcId:                 aws.String("vpc-aaaa66666"),
				State: &elbv2.LoadBalancerState{
					Code: aws.String("active"),
				},
				Type: aws.String("application"),
				AvailabilityZones: []*elbv2.AvailabilityZone{
					{
						ZoneName: aws.String("us-west-2c"),
						SubnetId: aws.String("subnet-1234eee"),
					},
					{
						ZoneName: aws.String("us-west-2d"),
						SubnetId: aws.String("subnet-1234fff"),
					},
				},
				SecurityGroups: []*string{
					aws.String("sg-1234asdf"),
				},
				IpAddressType: aws.String("ipv4"),
			},
		},
	}
	ExampleDescribeNetworkLoadBalancersOutput = &elbv2.DescribeLoadBalancersOutput{
		LoadBalancers: []*elbv2.LoadBalancer{
			{
				LoadBalancerArn:       aws.String("arn:aws:elasticloadbalancing:us-west-2:222222222222:loadbalancer/app/panther-test/bbbbbbbbbbbb"),
				DNSName:               aws.String("internal-panther-test-987654321.us-west-2.elb.amazonaws.com"),
				CanonicalHostedZoneId: aws.String("BBBB123"),
				CreatedTime:           &ExampleTime,
				LoadBalancerName:      aws.String("panther-test"),
				Scheme:                aws.String("internal"),
				VpcId:                 aws.String("vpc-bbbb66666"),
				State: &elbv2.LoadBalancerState{
					Code: aws.String("active"),
				},
				Type: aws.String("network"),
				AvailabilityZones: []*elbv2.AvailabilityZone{
					{
						ZoneName: aws.String("us-west-2c"),
						SubnetId: aws.String("subnet-1234eee"),
					},
					{
						ZoneName: aws.String("us-west-2d"),
						SubnetId: aws.String("subnet-1234fff"),
					},
				},
				SecurityGroups: []*string{
					aws.String("sg-1234asdf"),
				},
				IpAddressType: aws.String("ipv4"),
			},
		},
	}
	ExampleDescribeLoadBalancersOutputContinue = &elbv2.DescribeLoadBalancersOutput{
		LoadBalancers: []*elbv2.LoadBalancer{
			ExampleDescribeLoadBalancersOutput.LoadBalancers[0],
			ExampleDescribeLoadBalancersOutput.LoadBalancers[0],
		},
		NextMarker: aws.String("1"),
	}

	ExampleDescribeTags = &elbv2.DescribeTagsOutput{
		TagDescriptions: []*elbv2.TagDescription{
			{
				ResourceArn: ExampleDescribeLoadBalancersOutput.LoadBalancers[0].LoadBalancerArn,
				Tags: []*elbv2.Tag{
					{
						Key:   aws.String("KeyName1"),
						Value: aws.String("Value1"),
					},
				},
			},
		},
	}

	ExampleDescribeSSLPolicies = &elbv2.DescribeSSLPoliciesOutput{
		SslPolicies: []*elbv2.SslPolicy{
			{
				SslProtocols: []*string{
					aws.String("TLSv1"),
				},
				Ciphers: []*elbv2.Cipher{
					{
						Name:     aws.String("ECDHE"),
						Priority: aws.Int64(1),
					},
				},
				Name: aws.String("ELBSecurityPolicy1"),
			},
		},
	}

	ExampleDescribeListeners = &elbv2.DescribeListenersOutput{
		Listeners: []*elbv2.Listener{
			{
				ListenerArn:     aws.String("arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/load-balancer-listener/123/abc"),
				LoadBalancerArn: aws.String("arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/load-balancer/123"),
				Port:            aws.Int64(443),
				Protocol:        aws.String("HTTPS"),
				Certificates: []*elbv2.Certificate{
					{
						CertificateArn: aws.String("arn:aws:acm:us-west-2:123456789012:certificate/abc123"),
					},
				},
				SslPolicy: aws.String("ELBSecurityPolicy1"),
				DefaultActions: []*elbv2.Action{
					{
						Type:           aws.String("forward"),
						TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/routing-group/123abc"),
					},
				},
			},
		},
	}

	svcElbv2SetupCalls = map[string]func(*MockElbv2){
		"DescribeLoadBalancersPages": func(svc *MockElbv2) {
			svc.On("DescribeLoadBalancersPages", mock.Anything).
				Return(nil)
		},
		"DescribeListenersPages": func(svc *MockElbv2) {
			svc.On("DescribeListenersPages", mock.Anything).
				Return(nil)
		},
		"DescribeTags": func(svc *MockElbv2) {
			svc.On("DescribeTags", mock.Anything).
				Return(ExampleDescribeTags, nil)
		},
		"DescribeSSLPolicies": func(svc *MockElbv2) {
			svc.On("DescribeSSLPolicies", mock.Anything).
				Return(ExampleDescribeSSLPolicies, nil)
		},
	}

	svcElbv2SetupCallsError = map[string]func(*MockElbv2){
		"DescribeLoadBalancersPages": func(svc *MockElbv2) {
			svc.On("DescribeLoadBalancersPages", mock.Anything).
				Return(errors.New("ELBV2.DescribeLoadBalancersPages"))
		},
		"DescribeListenersPages": func(svc *MockElbv2) {
			svc.On("DescribeListenersPages", mock.Anything).
				Return(errors.New("ELBV2.DescribeListenersPages"))
		},
		"DescribeTags": func(svc *MockElbv2) {
			svc.On("DescribeTags", mock.Anything).
				Return(&elbv2.DescribeTagsOutput{},
					errors.New("ELBV2.DescribeTags error"),
				)
		},
		"DescribeSSLPolicies": func(svc *MockElbv2) {
			svc.On("DescribeSSLPolicies", mock.Anything).
				Return(&elbv2.DescribeSSLPoliciesOutput{},
					errors.New("ELBV2.DescribeSSLPolicies error"),
				)
		},
	}

	MockElbv2ForSetup = &MockElbv2{}
)

// Elbv2 mock

// SetupMockElbv2 is used to override the Elbv2 Client initializer
func SetupMockElbv2(_ *session.Session, _ *aws.Config) interface{} {
	return MockElbv2ForSetup
}

// MockElbv2 is a mock Elbv2 client
type MockElbv2 struct {
	elbv2iface.ELBV2API
	mock.Mock
}

// BuildMockElbv2Svc builds and returns a MockElbv2 struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockElbv2Svc(funcs []string) (mockSvc *MockElbv2) {
	mockSvc = &MockElbv2{}
	for _, f := range funcs {
		svcElbv2SetupCalls[f](mockSvc)
	}
	return
}

// BuildMockElbv2SvcError builds and returns a MockElbv2 struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockElbv2SvcError(funcs []string) (mockSvc *MockElbv2) {
	mockSvc = &MockElbv2{}
	for _, f := range funcs {
		svcElbv2SetupCallsError[f](mockSvc)
	}
	return
}

// BuildElbv2ServiceSvcAll builds and returns a MockElbv2 struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockElbv2SvcAll() (mockSvc *MockElbv2) {
	mockSvc = &MockElbv2{}
	for _, f := range svcElbv2SetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockElbv2SvcAllError builds and returns a MockElbv2 struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockElbv2SvcAllError() (mockSvc *MockElbv2) {
	mockSvc = &MockElbv2{}
	for _, f := range svcElbv2SetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockElbv2) DescribeLoadBalancers(in *elbv2.DescribeLoadBalancersInput) (*elbv2.DescribeLoadBalancersOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*elbv2.DescribeLoadBalancersOutput), args.Error(1)
}

func (m *MockElbv2) DescribeLoadBalancersPages(
	in *elbv2.DescribeLoadBalancersInput,
	paginationFunction func(*elbv2.DescribeLoadBalancersOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeLoadBalancersOutput, true)
	return args.Error(0)
}

func (m *MockElbv2) DescribeListenersPages(
	in *elbv2.DescribeListenersInput,
	paginationFunction func(*elbv2.DescribeListenersOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeListeners, true)
	return args.Error(0)
}

func (m *MockElbv2) DescribeTags(in *elbv2.DescribeTagsInput) (*elbv2.DescribeTagsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*elbv2.DescribeTagsOutput), args.Error(1)
}

func (m *MockElbv2) DescribeSSLPolicies(in *elbv2.DescribeSSLPoliciesInput) (*elbv2.DescribeSSLPoliciesOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*elbv2.DescribeSSLPoliciesOutput), args.Error(1)
}
