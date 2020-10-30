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
	"github.com/aws/aws-sdk-go/service/redshift"
	"github.com/aws/aws-sdk-go/service/redshift/redshiftiface"
	"github.com/stretchr/testify/mock"
)

// Example RDS API return values
var (
	ExampleDescribeClustersOutput = &redshift.DescribeClustersOutput{
		Clusters: []*redshift.Cluster{
			{
				ClusterIdentifier: aws.String("example-cluster"),
				NodeType:          aws.String("dc2.large"),
				ClusterStatus:     aws.String("available"),
				MasterUsername:    aws.String("awsuser"),
				DBName:            aws.String("dev"),
				Endpoint: &redshift.Endpoint{
					Address: aws.String("example-cluster.asdf123.us-west-2.redshift.amazonaws.com"),
					Port:    aws.Int64(5439),
				},
				ClusterCreateTime:                &ExampleTime,
				AutomatedSnapshotRetentionPeriod: aws.Int64(1),
				ManualSnapshotRetentionPeriod:    aws.Int64(-1),
				ClusterParameterGroups: []*redshift.ClusterParameterGroupStatus{
					{
						ParameterGroupName:   aws.String("default.redshift-1.0"),
						ParameterApplyStatus: aws.String("in-sync"),
					},
				},
				ClusterSubnetGroupName:     aws.String("default"),
				VpcId:                      aws.String("vpc-asdfasdf"),
				AvailabilityZone:           aws.String("us-west-2c"),
				PreferredMaintenanceWindow: aws.String("sat:10:30-sat:11:00"),
				ClusterVersion:             aws.String("1.0"),
				AllowVersionUpgrade:        aws.Bool(true),
				NumberOfNodes:              aws.Int64(2),
				PubliclyAccessible:         aws.Bool(true),
				Encrypted:                  aws.Bool(false),
				ClusterPublicKey:           aws.String("ssh-rsa keyhash123 Amazon-Redshift\n"),
				ClusterNodes: []*redshift.ClusterNode{
					{
						NodeRole:         aws.String("LEADER"),
						PrivateIPAddress: aws.String("172.0.0.0"),
						PublicIPAddress:  aws.String("54.0.0.1"),
					},
					{
						NodeRole:         aws.String("COMPUTE-1"),
						PrivateIPAddress: aws.String("172.0.0.1"),
						PublicIPAddress:  aws.String("34.0.0.0"),
					},
				},
				ClusterRevisionNumber:            aws.String("7804"),
				EnhancedVpcRouting:               aws.Bool(false),
				MaintenanceTrackName:             aws.String("current"),
				ElasticResizeNumberOfNodeOptions: aws.String("[4]"),
			},
		},
	}

	ExampleDescribeClustersOutputContinue = &redshift.DescribeClustersOutput{
		Clusters: []*redshift.Cluster{
			ExampleDescribeClustersOutput.Clusters[0],
			ExampleDescribeClustersOutput.Clusters[0],
		},
		Marker: aws.String("1"),
	}

	ExampleLoggingStatus = &redshift.LoggingStatus{
		LoggingEnabled: aws.Bool(false),
	}

	svcRedshiftSetupCalls = map[string]func(*MockRedshift){
		"DescribeClustersPages": func(svc *MockRedshift) {
			svc.On("DescribeClustersPages", mock.Anything).
				Return(nil)
		},
		"DescribeLoggingStatus": func(svc *MockRedshift) {
			svc.On("DescribeLoggingStatus", mock.Anything).
				Return(ExampleLoggingStatus, nil)
		},
	}

	svcRedshiftSetupCallsError = map[string]func(*MockRedshift){
		"DescribeClustersPages": func(svc *MockRedshift) {
			svc.On("DescribeClustersPages", mock.Anything).
				Return(errors.New("Redshift.DescribeClustersPages error"))
		},
		"DescribeLoggingStatus": func(svc *MockRedshift) {
			svc.On("DescribeLoggingStatus", mock.Anything).
				Return(&redshift.LoggingStatus{},
					errors.New("Redshift.DescribeLoggingStatus error"),
				)
		},
	}

	MockRedshiftForSetup = &MockRedshift{}
)

// Redshift mock

// SetupMockRedshift is used to override the Redshift Client initializer
func SetupMockRedshift(_ *session.Session, _ *aws.Config) interface{} {
	return MockRedshiftForSetup
}

// MockRedshift is a mock Redshift client
type MockRedshift struct {
	redshiftiface.RedshiftAPI
	mock.Mock
}

// BuildMockRedshiftSvc builds and returns a MockRedshift struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockRedshiftSvc(funcs []string) (mockSvc *MockRedshift) {
	mockSvc = &MockRedshift{}
	for _, f := range funcs {
		svcRedshiftSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockRedshiftSvcError builds and returns a MockRedshift struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockRedshiftSvcError(funcs []string) (mockSvc *MockRedshift) {
	mockSvc = &MockRedshift{}
	for _, f := range funcs {
		svcRedshiftSetupCallsError[f](mockSvc)
	}
	return
}

// BuildRedshiftServiceSvcAll builds and returns a MockRedshift struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockRedshiftSvcAll() (mockSvc *MockRedshift) {
	mockSvc = &MockRedshift{}
	for _, f := range svcRedshiftSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockRedshiftSvcAllError builds and returns a MockRedshift struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockRedshiftSvcAllError() (mockSvc *MockRedshift) {
	mockSvc = &MockRedshift{}
	for _, f := range svcRedshiftSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockRedshift) DescribeClustersPages(
	in *redshift.DescribeClustersInput,
	paginationFunction func(*redshift.DescribeClustersOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeClustersOutput, true)
	return args.Error(0)
}

func (m *MockRedshift) DescribeLoggingStatus(in *redshift.DescribeLoggingStatusInput) (*redshift.LoggingStatus, error) {
	args := m.Called(in)
	return args.Get(0).(*redshift.LoggingStatus), args.Error(1)
}
