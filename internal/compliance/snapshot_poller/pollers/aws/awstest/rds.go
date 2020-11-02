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
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"
	"github.com/stretchr/testify/mock"
)

// Example RDS API return values
var (
	ExampleRDSInstanceName = aws.String("example-instance")

	ExampleRDSSnapshotID = aws.String("example-snapshot-id")

	ExampleDescribeDBSnapshotsAttributesOutput = &rds.DescribeDBSnapshotAttributesOutput{
		DBSnapshotAttributesResult: &rds.DBSnapshotAttributesResult{
			DBSnapshotIdentifier: aws.String("test-snapshot-1"),
			DBSnapshotAttributes: []*rds.DBSnapshotAttribute{
				{
					AttributeName: aws.String("restore"),
				},
			},
		},
	}

	ExampleDescribeDBInstancesOutput = &rds.DescribeDBInstancesOutput{
		DBInstances: []*rds.DBInstance{
			{
				DBInstanceIdentifier: ExampleRDSInstanceName,
				DBInstanceClass:      aws.String("db.t2.micro"),
				Engine:               aws.String("mysql"),
				DBInstanceStatus:     aws.String("available"),
				MasterUsername:       aws.String("superuser"),
				DBName:               aws.String("db_1"),
				Endpoint: &rds.Endpoint{
					Address:      aws.String("example-instance.1111.us-west-2.rds.amazonaws.com"),
					Port:         aws.Int64(3306),
					HostedZoneId: aws.String("ABCDE1234"),
				},
				AllocatedStorage:      aws.Int64(20),
				InstanceCreateTime:    &ExampleTime,
				PreferredBackupWindow: aws.String("07:31-08:01"),
				BackupRetentionPeriod: aws.Int64(7),
				VpcSecurityGroups: []*rds.VpcSecurityGroupMembership{
					{
						VpcSecurityGroupId: aws.String("sg-123456789"),
						Status:             aws.String("active"),
					},
				},
				DBParameterGroups: []*rds.DBParameterGroupStatus{
					{
						DBParameterGroupName: aws.String("default.mysql5.7"),
						ParameterApplyStatus: aws.String("in-sync"),
					},
				},
				AvailabilityZone: aws.String("us-west-2a"),
				DBSubnetGroup: &rds.DBSubnetGroup{
					DBSubnetGroupName:        aws.String("default"),
					DBSubnetGroupDescription: aws.String("default"),
					VpcId:                    aws.String("vpc-asdfasdf"),
					SubnetGroupStatus:        aws.String("Complete"),
					Subnets: []*rds.Subnet{
						{
							SubnetIdentifier: aws.String("subnet-asdfasdfasdf"),
							SubnetAvailabilityZone: &rds.AvailabilityZone{
								Name: aws.String("us-west-2d"),
							},
							SubnetStatus: aws.String("Active"),
						},
						{
							SubnetIdentifier: aws.String("subnet-1234567"),
							SubnetAvailabilityZone: &rds.AvailabilityZone{
								Name: aws.String("us-west-2c"),
							},
							SubnetStatus: aws.String("Active"),
						},
						{
							SubnetIdentifier: aws.String("subnet-asdfasdf123"),
							SubnetAvailabilityZone: &rds.AvailabilityZone{
								Name: aws.String("us-west-2a"),
							},
							SubnetStatus: aws.String("Active"),
						},
						{
							SubnetIdentifier: aws.String("subnet-asdfadsf123"),
							SubnetAvailabilityZone: &rds.AvailabilityZone{
								Name: aws.String("us-west-2b"),
							},
							SubnetStatus: aws.String("Active"),
						},
					},
				},
				PreferredMaintenanceWindow: aws.String("thu:12:02-thu:12:32"),
				LatestRestorableTime:       &ExampleTime,
				MultiAZ:                    aws.Bool(false),
				EngineVersion:              aws.String("5.7.22"),
				AutoMinorVersionUpgrade:    aws.Bool(true),
				LicenseModel:               aws.String("general-public-license"),
				OptionGroupMemberships: []*rds.OptionGroupMembership{
					{
						OptionGroupName: aws.String("default:mysql-5-7"),
						Status:          aws.String("in-sync"),
					},
				},
				PubliclyAccessible:               aws.Bool(false),
				StorageType:                      aws.String("gp2"),
				DbInstancePort:                   aws.Int64(0),
				StorageEncrypted:                 aws.Bool(false),
				DbiResourceId:                    aws.String("db-ASDFADLKJ"),
				CACertificateIdentifier:          aws.String("rds-ca-2015"),
				CopyTagsToSnapshot:               aws.Bool(true),
				MonitoringInterval:               aws.Int64(0),
				DBInstanceArn:                    aws.String("arn:aws:rds:us-west-2:123456789012:db:example-instance"),
				IAMDatabaseAuthenticationEnabled: aws.Bool(false),
				PerformanceInsightsEnabled:       aws.Bool(false),
				DeletionProtection:               aws.Bool(true),
			},
		},
	}
	ExampleDescribeDBInstancesOutputContinue = &rds.DescribeDBInstancesOutput{
		DBInstances: []*rds.DBInstance{
			ExampleDescribeDBInstancesOutput.DBInstances[0],
			ExampleDescribeDBInstancesOutput.DBInstances[0],
		},
		Marker: aws.String("1"),
	}

	ExampleDescribeDBSnapshotsOutput = &rds.DescribeDBSnapshotsOutput{
		DBSnapshots: []*rds.DBSnapshot{
			{
				DBSnapshotIdentifier:             aws.String("rds:example-instance-2019-01-01-01-01"),
				DBInstanceIdentifier:             aws.String("example-instance"),
				SnapshotCreateTime:               &ExampleTime,
				Engine:                           aws.String("mysql"),
				AllocatedStorage:                 aws.Int64(20),
				Status:                           aws.String("available"),
				Port:                             aws.Int64(3306),
				AvailabilityZone:                 aws.String("us-west-2a"),
				VpcId:                            aws.String("vpc-asdfasdf"),
				InstanceCreateTime:               &ExampleTime,
				MasterUsername:                   aws.String("superuser"),
				EngineVersion:                    aws.String("5.7.22"),
				LicenseModel:                     aws.String("general-public-license"),
				SnapshotType:                     aws.String("automated"),
				OptionGroupName:                  aws.String("default:mysql-5-7"),
				PercentProgress:                  aws.Int64(100),
				StorageType:                      aws.String("gp2"),
				Encrypted:                        aws.Bool(false),
				DBSnapshotArn:                    aws.String("arn:aws:rds:us-west-2:111111111111:snapshot:rds:example-instance-2019-01-01-01-01"),
				IAMDatabaseAuthenticationEnabled: aws.Bool(false),
				DbiResourceId:                    aws.String("db-asdfasdfasdfasdf"),
			},
		},
	}

	ExampleListTagsForResourceRds = &rds.ListTagsForResourceOutput{
		TagList: []*rds.Tag{
			{
				Key:   aws.String("Key1"),
				Value: aws.String("Value1"),
			},
		},
	}

	svcRdsSetupCalls = map[string]func(*MockRds){
		"DescribeDBInstancesPages": func(svc *MockRds) {
			svc.On("DescribeDBInstancesPages", mock.Anything).
				Return(nil)
		},
		"DescribeDBSnapshotsPages": func(svc *MockRds) {
			svc.On("DescribeDBSnapshotsPages", mock.Anything).
				Return(nil)
		},
		"DescribeDBSnapshotAttributes": func(svc *MockRds) {
			svc.On("DescribeDBSnapshotAttributes", mock.Anything).
				Return(ExampleDescribeDBSnapshotsAttributesOutput, nil)
		},
		"ListTagsForResource": func(svc *MockRds) {
			svc.On("ListTagsForResource", mock.Anything).
				Return(ExampleListTagsForResourceRds, nil)
		},
	}

	svcRdsSetupCallsError = map[string]func(*MockRds){
		"DescribeDBInstancesPages": func(svc *MockRds) {
			svc.On("DescribeDBInstancesPages", mock.Anything).
				Return(errors.New("RDS.DescribeDBInstancesPages error"))
		},
		"DescribeDBSnapshotsPages": func(svc *MockRds) {
			svc.On("DescribeDBSnapshotsPages", mock.Anything).
				Return(errors.New("RDS.DescribeDBSnapshotsPages error"))
		},
		"DescribeDBSnapshotAttributes": func(svc *MockRds) {
			svc.On("DescribeDBSnapshotAttributes", mock.Anything).
				Return(&rds.DescribeDBSnapshotAttributesOutput{},
					errors.New("RDS.DescribeSnapshotAttributes error"),
				)
		},
		"ListTagsForResource": func(svc *MockRds) {
			svc.On("ListTagsForResource", mock.Anything).
				Return(&rds.ListTagsForResourceOutput{},
					errors.New("RDS.ListTagsForResource error"),
				)
		},
	}

	MockRdsForSetup = &MockRds{}
)

// RDS mock

// SetupMockRds is used to override the RDS Client initializer
func SetupMockRds(_ *session.Session, _ *aws.Config) interface{} {
	return MockRdsForSetup
}

// MockRds is a mock RDS client
type MockRds struct {
	rdsiface.RDSAPI
	mock.Mock
}

// BuildMockRdsSvc builds and returns a MockRds struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockRdsSvc(funcs []string) (mockSvc *MockRds) {
	mockSvc = &MockRds{}
	for _, f := range funcs {
		svcRdsSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockRdsSvcError builds and returns a MockRds struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockRdsSvcError(funcs []string) (mockSvc *MockRds) {
	mockSvc = &MockRds{}
	for _, f := range funcs {
		svcRdsSetupCallsError[f](mockSvc)
	}
	return
}

// BuildRdsServiceSvcAll builds and returns a MockRds struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockRdsSvcAll() (mockSvc *MockRds) {
	mockSvc = &MockRds{}
	for _, f := range svcRdsSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockRdsSvcAllError builds and returns a MockRds struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockRdsSvcAllError() (mockSvc *MockRds) {
	mockSvc = &MockRds{}
	for _, f := range svcRdsSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockRds) DescribeDBInstancesPages(
	in *rds.DescribeDBInstancesInput,
	paginationFunction func(*rds.DescribeDBInstancesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeDBInstancesOutput, true)
	return args.Error(0)
}

func (m *MockRds) DescribeDBSnapshotsPages(
	in *rds.DescribeDBSnapshotsInput,
	paginationFunction func(*rds.DescribeDBSnapshotsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeDBSnapshotsOutput, true)
	return args.Error(0)
}

func (m *MockRds) DescribeDBSnapshotAttributes(in *rds.DescribeDBSnapshotAttributesInput) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*rds.DescribeDBSnapshotAttributesOutput), args.Error(1)
}

func (m *MockRds) ListTagsForResource(in *rds.ListTagsForResourceInput) (*rds.ListTagsForResourceOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*rds.ListTagsForResourceOutput), args.Error(1)
}
