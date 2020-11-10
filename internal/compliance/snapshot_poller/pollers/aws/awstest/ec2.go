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
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/stretchr/testify/mock"
)

var (
	//
	// Example VPCs
	//

	ExampleInstanceId = aws.String("instance-aabbcc123")
	ExampleVpcId      = aws.String("vpc-aabbccddee123")
	ExampleVolumeId   = aws.String("vol-aaabbbccc123123")
	ExampleSnapshotId = aws.String("snapshot-aaabbbccc123123")

	ExampleInstance = &ec2.Instance{
		AmiLaunchIndex: aws.Int64(0),
		ImageId:        aws.String("ami-111222333444555666"),
		InstanceId:     ExampleInstanceId,
		InstanceType:   aws.String("t2.micro"),
		KeyName:        aws.String("ec2-instance-key-pair"),
		LaunchTime:     &ExampleTime,
		Monitoring: &ec2.Monitoring{
			State: aws.String("disabled"),
		},
		Placement: &ec2.Placement{
			AvailabilityZone: aws.String("us-west-2b"),
			GroupName:        aws.String(""),
			Tenancy:          aws.String("default"),
		},
		PrivateDnsName:   aws.String("ip-172-0-0-0.us-west-2.compute.internal"),
		PrivateIpAddress: aws.String("172.0.0.0"),
		ProductCodes:     []*ec2.ProductCode{},
		PublicDnsName:    aws.String("ec2-54-0-0-0.us-west-2.compute.amazonaws.com"),
		PublicIpAddress:  aws.String("54.0.0.0"),
		State: &ec2.InstanceState{
			Code: aws.Int64(16),
			Name: aws.String("running"),
		},
		StateTransitionReason: aws.String(""),
		SubnetId:              aws.String("subnet-123123"),
		VpcId:                 ExampleVpcId,
		Architecture:          aws.String("x86_64"),
		BlockDeviceMappings: []*ec2.InstanceBlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/sda1"),
				Ebs: &ec2.EbsInstanceBlockDevice{
					AttachTime:          &ExampleTime,
					DeleteOnTermination: aws.Bool(true),
					Status:              aws.String("attached"),
					VolumeId:            ExampleVolumeId,
				},
			},
		},
		ClientToken:  aws.String(""),
		EbsOptimized: aws.Bool(false),
		EnaSupport:   aws.Bool(true),
		Hypervisor:   aws.String("xen"),
		NetworkInterfaces: []*ec2.InstanceNetworkInterface{
			{
				Association: &ec2.InstanceNetworkInterfaceAssociation{
					IpOwnerId:     aws.String("123456789012"),
					PublicDnsName: aws.String("ec2-54-0-0-0.us-west-2.compute.amazonaws.com"),
					PublicIp:      aws.String("54.0.0.0"),
				},
				Attachment: &ec2.InstanceNetworkInterfaceAttachment{
					AttachTime:          &ExampleTime,
					AttachmentId:        aws.String("eni-attach-112233445566"),
					DeleteOnTermination: aws.Bool(true),
					DeviceIndex:         aws.Int64(0),
					Status:              aws.String("attached"),
				},
				Description: aws.String(""),
				Groups: []*ec2.GroupIdentifier{
					{
						GroupName: aws.String("launch-wizard-1"),
						GroupId:   aws.String("sg-0123abcde1234"),
					},
				},
				Ipv6Addresses:      []*ec2.InstanceIpv6Address{},
				MacAddress:         aws.String("DE:AD:BE:EF:00:00"),
				NetworkInterfaceId: aws.String("eni-000111222333"),
				OwnerId:            aws.String("123456789012"),
				PrivateDnsName:     aws.String("ip-172-0-0-0.us-west-2.compute.internal"),
				PrivateIpAddress:   aws.String("172.0.0.0"),
				PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
					{
						Association: &ec2.InstanceNetworkInterfaceAssociation{
							IpOwnerId:     aws.String("123456789012"),
							PublicDnsName: aws.String("ec2-54-0-0-0.us-west-2.compute.amazonaws.com"),
							PublicIp:      aws.String("54.0.0.0"),
						},
						Primary:          aws.Bool(true),
						PrivateDnsName:   aws.String("ip-172-0-0-0.us-west-2.compute.internal"),
						PrivateIpAddress: aws.String("172.0.0.0"),
					},
				},
				SourceDestCheck: aws.Bool(true),
				Status:          aws.String("in-use"),
				SubnetId:        aws.String("subnet-basdf123"),
				VpcId:           ExampleVpcId,
			},
		},
		RootDeviceName: aws.String("/dev/sda1"),
		RootDeviceType: aws.String("ebs"),
		SecurityGroups: []*ec2.GroupIdentifier{
			{
				GroupName: aws.String("launch-wizard-1"),
				GroupId:   aws.String("sg-0001122334455"),
			},
		},
		SourceDestCheck:    aws.Bool(true),
		VirtualizationType: aws.String("hvm"),
		CpuOptions: &ec2.CpuOptions{
			CoreCount:      aws.Int64(1),
			ThreadsPerCore: aws.Int64(1),
		},
		CapacityReservationSpecification: &ec2.CapacityReservationSpecificationResponse{
			CapacityReservationPreference: aws.String("open"),
		},
		HibernationOptions: &ec2.HibernationOptions{
			Configured: aws.Bool(false),
		},
	}

	ExampleDescribeInstancesOutput = &ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				Instances: []*ec2.Instance{
					ExampleInstance,
				},
			},
		},
	}

	ExampleDescribeInstancesOutputContinue = &ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				Instances: []*ec2.Instance{
					ExampleInstance,
					ExampleInstance,
				},
			},
		},
		NextToken: aws.String("1"),
	}

	ExampleDescribeVolumesOutput = &ec2.DescribeVolumesOutput{
		Volumes: []*ec2.Volume{
			{
				Attachments: []*ec2.VolumeAttachment{
					{
						AttachTime:          &ExampleTime,
						Device:              aws.String("/dev/sda1"),
						InstanceId:          ExampleInstanceId,
						State:               aws.String("attached"),
						VolumeId:            ExampleVolumeId,
						DeleteOnTermination: aws.Bool(true),
					},
				},
				AvailabilityZone: aws.String("us-west-2b"),
				CreateTime:       &ExampleTime,
				Encrypted:        aws.Bool(false),
				Size:             aws.Int64(10),
				SnapshotId:       aws.String("snap-abcdefg012345"),
				State:            aws.String("in-use"),
				VolumeId:         ExampleVolumeId,
				Iops:             aws.Int64(100),
				VolumeType:       aws.String("gp2"),
			},
		},
	}
	ExampleDescribeVolumesOutputContinue = &ec2.DescribeVolumesOutput{
		Volumes: []*ec2.Volume{
			ExampleDescribeVolumesOutput.Volumes[0],
			ExampleDescribeVolumesOutput.Volumes[0],
		},
		NextToken: aws.String("1"),
	}

	ExampleDescribeImagesOutput = &ec2.DescribeImagesOutput{
		Images: []*ec2.Image{
			{
				Architecture:        aws.String("x86_64"),
				CreationDate:        aws.String("2011-11-04T12:34:17.000Z"),
				ImageId:             aws.String("ari-abc234"),
				ImageLocation:       aws.String("ubuntu-us-west-2/kernels/ubuntu.xml"),
				ImageType:           aws.String("ramdisk"),
				Public:              aws.Bool(true),
				OwnerId:             aws.String("123456789012"),
				State:               aws.String("available"),
				BlockDeviceMappings: []*ec2.BlockDeviceMapping{},
				Hypervisor:          aws.String("xen"),
				Name:                aws.String("ubuntu/image"),
				RootDeviceType:      aws.String("instance-store"),
				VirtualizationType:  aws.String("paravirtual"),
			},
			{
				Architecture:        aws.String("i386"),
				CreationDate:        aws.String("2011-11-04T12:36:14.000Z"),
				ImageId:             aws.String("ari-xyz789"),
				ImageLocation:       aws.String("ubuntu-us-west-2/kernels/ubuntu-2.xml"),
				ImageType:           aws.String("ramdisk"),
				Public:              aws.Bool(true),
				OwnerId:             aws.String("123456789013"),
				State:               aws.String("available"),
				BlockDeviceMappings: []*ec2.BlockDeviceMapping{},
				Hypervisor:          aws.String("xen"),
				Name:                aws.String("ubuntu/kernels/ubuntu/other-image"),
				RootDeviceType:      aws.String("instance-store"),
				VirtualizationType:  aws.String("paravirtual"),
			},
			{
				Architecture:        aws.String("i386"),
				CreationDate:        aws.String("2011-11-04T12:36:14.000Z"),
				ImageId:             aws.String("ami-111222333444555666"),
				ImageLocation:       aws.String("ubuntu-us-west-2/kernels/ubuntu-2.xml"),
				ImageType:           aws.String("ramdisk"),
				Public:              aws.Bool(true),
				OwnerId:             aws.String("123456789013"),
				State:               aws.String("available"),
				BlockDeviceMappings: []*ec2.BlockDeviceMapping{},
				Hypervisor:          aws.String("xen"),
				Name:                aws.String("ubuntu/kernels/ubuntu/other-image"),
				RootDeviceType:      aws.String("instance-store"),
				VirtualizationType:  aws.String("paravirtual"),
			},
		},
	}

	ExampleAmi = &ec2.Image{
		Architecture:        aws.String("x86_64"),
		CreationDate:        aws.String("2011-11-04T12:34:17.000Z"),
		ImageId:             aws.String("ari-abc234"),
		ImageLocation:       aws.String("ubuntu-us-west-2/kernels/ubuntu.xml"),
		ImageType:           aws.String("ramdisk"),
		Public:              aws.Bool(true),
		OwnerId:             aws.String("123456789012"),
		State:               aws.String("available"),
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{},
		Hypervisor:          aws.String("xen"),
		Name:                aws.String("ubuntu/image"),
		RootDeviceType:      aws.String("instance-store"),
		VirtualizationType:  aws.String("paravirtual"),
	}

	ExampleVpc = &ec2.Vpc{
		CidrBlock:     aws.String("172.31.0.0/16"),
		DhcpOptionsId: aws.String("dopt-63f9231b"),
		CidrBlockAssociationSet: []*ec2.VpcCidrBlockAssociation{
			{
				AssociationId: aws.String("vpc-cidr-assoc-dfb6ceb5"),
				CidrBlock:     aws.String("172.31.0.0/16"),
				CidrBlockState: &ec2.VpcCidrBlockState{
					State: aws.String("associated"),
				},
			},
		},
		State:           aws.String("available"),
		InstanceTenancy: aws.String("default"),
		IsDefault:       aws.Bool(true),
		OwnerId:         aws.String("123456789012"),
		VpcId:           aws.String("vpc-6aa60b12"),
	}

	ExampleDescribeVpcsOutput = &ec2.DescribeVpcsOutput{
		Vpcs: []*ec2.Vpc{
			ExampleVpc,
		},
	}

	ExampleDescribeVpcsOutputContinue = &ec2.DescribeVpcsOutput{
		Vpcs: []*ec2.Vpc{
			ExampleVpc,
			ExampleVpc,
		},
		NextToken: aws.String("1"),
	}

	ExampleDescribeSecurityGroupsOutput = &ec2.DescribeSecurityGroupsOutput{
		SecurityGroups: []*ec2.SecurityGroup{
			{
				Description: aws.String("default VPC security group"),
				GroupId:     aws.String("sg-111222333"),
				GroupName:   aws.String("default"),
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("-1"),
					},
				},
				IpPermissionsEgress: []*ec2.IpPermission{},
				OwnerId:             aws.String("123456789012"),
				VpcId:               aws.String("vpc-6aa60b12"),
			},
		},
	}
	ExampleDescribeSecurityGroupsOutputContinue = &ec2.DescribeSecurityGroupsOutput{
		SecurityGroups: []*ec2.SecurityGroup{
			ExampleDescribeSecurityGroupsOutput.SecurityGroups[0],
			ExampleDescribeSecurityGroupsOutput.SecurityGroups[0],
		},
		NextToken: aws.String("1"),
	}

	ExampleDescribeNetworkAclsOutput = &ec2.DescribeNetworkAclsOutput{
		NetworkAcls: []*ec2.NetworkAcl{
			{
				Associations: []*ec2.NetworkAclAssociation{
					{
						NetworkAclAssociationId: aws.String("aclassoc-111222333"),
						NetworkAclId:            aws.String("acl-111222333"),
						SubnetId:                aws.String("subnet-111222333"),
					},
				},
				Entries: []*ec2.NetworkAclEntry{
					{
						CidrBlock:  aws.String("0.0.0.0/0"),
						Egress:     aws.Bool(true),
						Protocol:   aws.String("-1"),
						RuleAction: aws.String("allow"),
						RuleNumber: aws.Int64(100),
					},
				},
				IsDefault:    aws.Bool(true),
				NetworkAclId: aws.String("acl-111222333"),
				OwnerId:      aws.String("123456789012"),
				VpcId:        aws.String("vpc-6aa60b12"),
			},
		},
	}

	ExampleDescribeNetworkAclsOutputContinue = &ec2.DescribeNetworkAclsOutput{
		NetworkAcls: []*ec2.NetworkAcl{
			ExampleDescribeNetworkAclsOutput.NetworkAcls[0],
			ExampleDescribeNetworkAclsOutput.NetworkAcls[0],
		},
		NextToken: aws.String("1"),
	}

	ExampleDescribeFlowLogsOutput = &ec2.DescribeFlowLogsOutput{
		FlowLogs: []*ec2.FlowLog{
			{
				CreationTime:             &ExampleTime,
				DeliverLogsPermissionArn: aws.String("arn:aws:iam::123456789012:role/PantherDevNickAdministrator"),
				DeliverLogsStatus:        aws.String("SUCCESS"),
				FlowLogStatus:            aws.String("ACTIVE"),
				LogDestination:           aws.String("arn:aws:logs:us-west-2:123456789012:log-group:vpc-flow-test"),
				LogDestinationType:       aws.String("cloud-watch-logs"),
				LogGroupName:             aws.String("vpc-flow-test"),
				ResourceId:               aws.String("vpc-6aa60b12"),
				TrafficType:              aws.String("REJECT"),
			},
		},
	}

	ExampleDescribeRouteTablesOutput = &ec2.DescribeRouteTablesOutput{
		RouteTables: []*ec2.RouteTable{
			{
				OwnerId:      aws.String("123456789012"),
				RouteTableId: aws.String("rtb-8b28a7f0"),
				Associations: []*ec2.RouteTableAssociation{
					{
						Main:                    aws.Bool(true),
						RouteTableAssociationId: aws.String("rtbassoc-8184e8fc"),
						RouteTableId:            aws.String("rtb-8b28a7f0"),
					},
				},
				Routes: []*ec2.Route{
					{
						DestinationCidrBlock: aws.String("172.31.0.0/16"),
						GatewayId:            aws.String("local"),
						Origin:               aws.String("CreateRouteTable"),
						State:                aws.String("active"),
					},
					{
						DestinationCidrBlock: aws.String("0.0.0.0/0"),
						GatewayId:            aws.String("igw-a4b1a6c2"),
						Origin:               aws.String("CreateRoute"),
						State:                aws.String("active"),
					},
				},
				VpcId: aws.String("vpc-6aa60b12"),
			},
		},
	}

	ExampleDescribeStaleSecurityGroups = &ec2.DescribeStaleSecurityGroupsOutput{
		StaleSecurityGroupSet: []*ec2.StaleSecurityGroup{
			{
				Description: aws.String("example security group"),
				GroupId:     aws.String("sg-111222333"),
				GroupName:   aws.String("default"),
				StaleIpPermissionsEgress: []*ec2.StaleIpPermission{
					{
						FromPort:   aws.Int64(5555),
						IpProtocol: aws.String("tcp"),
						ToPort:     aws.Int64(5555),
						UserIdGroupPairs: []*ec2.UserIdGroupPair{
							{
								GroupId:                aws.String("sg-444555666"),
								GroupName:              aws.String("default"),
								PeeringStatus:          aws.String("deleted"),
								UserId:                 aws.String("123456789012"),
								VpcId:                  aws.String("vpc-112233445566"),
								VpcPeeringConnectionId: aws.String("pcx-112233445566"),
							},
						},
					},
				},
				VpcId: aws.String("vpc-111222333444"),
			},
		},
	}

	ExampleDescribeRegionsOutput = &ec2.DescribeRegionsOutput{
		Regions: []*ec2.Region{
			{
				Endpoint:   aws.String("ec2.ap-southeast-2.amazonaws.com"),
				RegionName: aws.String("ap-southeast-2"),
			},
			{
				Endpoint:   aws.String("ec2.eu-central-1.amazonaws.com"),
				RegionName: aws.String("eu-central-1"),
			},
			{
				Endpoint:   aws.String("ec2.us-west-2.amazonaws.com"),
				RegionName: aws.String("us-west-2"),
			},
		},
	}

	ExampleDescribeSnapshots = &ec2.DescribeSnapshotsOutput{
		Snapshots: []*ec2.Snapshot{
			{
				Description: aws.String("Copied for destinationAmi..."),
				Encrypted:   aws.Bool(false),
				OwnerId:     ExampleAccountId,
				Progress:    aws.String("100%"),
				SnapshotId:  ExampleSnapshotId,
				StartTime:   &ExampleTime,
				State:       aws.String("completed"),
				VolumeId:    ExampleVolumeId,
				VolumeSize:  aws.Int64(16),
			},
		},
	}

	ExampleDescribeSnapshotAttribute = &ec2.DescribeSnapshotAttributeOutput{
		SnapshotId: ExampleSnapshotId,
		CreateVolumePermissions: []*ec2.CreateVolumePermission{
			{
				Group:  aws.String("GroupName"),
				UserId: aws.String("user-123"),
			},
		},
		ProductCodes: []*ec2.ProductCode{
			{
				ProductCodeId:   aws.String("id-123"),
				ProductCodeType: aws.String("PremiumSubscription"),
			},
		},
	}

	svcEC2SetupCalls = map[string]func(*MockEC2){
		"DescribeInstancesPages": func(svc *MockEC2) {
			svc.On("DescribeInstancesPages", mock.Anything).
				Return(nil)
		},
		"DescribeVolumesPages": func(svc *MockEC2) {
			svc.On("DescribeVolumesPages", mock.Anything).
				Return(nil)
		},
		"DescribeVpcsPages": func(svc *MockEC2) {
			svc.On("DescribeVpcsPages", mock.Anything).
				Return(nil)
		},
		"DescribeRouteTablesPages": func(svc *MockEC2) {
			svc.On("DescribeRouteTablesPages", mock.Anything).
				Return(nil)
		},
		"DescribeFlowLogsPages": func(svc *MockEC2) {
			svc.On("DescribeFlowLogsPages", mock.Anything).
				Return(nil)
		},
		"DescribeSecurityGroupsPages": func(svc *MockEC2) {
			svc.On("DescribeSecurityGroupsPages", mock.Anything).
				Return(nil)
		},
		"DescribeNetworkAclsPages": func(svc *MockEC2) {
			svc.On("DescribeNetworkAclsPages", mock.Anything).
				Return(nil)
		},
		"DescribeStaleSecurityGroupsPages": func(svc *MockEC2) {
			svc.On("DescribeStaleSecurityGroupsPages", mock.Anything).
				Return(nil)
		},
		"DescribeSnapshotsPages": func(svc *MockEC2) {
			svc.On("DescribeSnapshotsPages", mock.Anything).
				Return(nil)
		},
		"DescribeImages": func(svc *MockEC2) {
			svc.On("DescribeImages", mock.Anything).
				Return(ExampleDescribeImagesOutput, nil)
		},
		"DescribeSecurityGroups": func(svc *MockEC2) {
			svc.On("DescribeSecurityGroups", mock.Anything).
				Return(ExampleDescribeSecurityGroupsOutput, nil)
		},
		"DescribeNetworkAcls": func(svc *MockEC2) {
			svc.On("DescribeNetworkAcls", mock.Anything).
				Return(ExampleDescribeNetworkAclsOutput, nil)
		},
		"DescribeRegions": func(svc *MockEC2) {
			svc.On("DescribeRegions", mock.Anything).
				Return(ExampleDescribeRegionsOutput, nil)
		},
		"DescribeSnapshotAttribute": func(svc *MockEC2) {
			svc.On("DescribeSnapshotAttribute", mock.Anything).
				Return(ExampleDescribeSnapshotAttribute, nil)
		},
	}

	svcEC2SetupCallsError = map[string]func(*MockEC2){
		"DescribeInstancesPages": func(svc *MockEC2) {
			svc.On("DescribeInstancesPages", mock.Anything).
				Return(errors.New("EC2.DescribeInstancesPages error"))
		},
		"DescribeVolumesPages": func(svc *MockEC2) {
			svc.On("DescribeVolumesPages", mock.Anything).
				Return(errors.New("EC2.DescribeVolumesPages error"))
		},
		"DescribeVpcsPages": func(svc *MockEC2) {
			svc.On("DescribeVpcsPages", mock.Anything).
				Return(errors.New("EC2.DescribeVpcsPages error"))
		},
		"DescribeRouteTablesPages": func(svc *MockEC2) {
			svc.On("DescribeRouteTablesPages", mock.Anything).
				Return(errors.New("EC2.DescribeRouteTablesPages error"))
		},
		"DescribeFlowLogsPages": func(svc *MockEC2) {
			svc.On("DescribeFlowLogsPages", mock.Anything).
				Return(errors.New("EC2.DescribeFlowLogsPages error"))
		},
		"DescribeSecurityGroupsPages": func(svc *MockEC2) {
			svc.On("DescribeSecurityGroupsPages", mock.Anything).
				Return(errors.New("EC2.DescribeSecurityGroupsPages error"))
		},
		"DescribeNetworkAclsPages": func(svc *MockEC2) {
			svc.On("DescribeNetworkAclsPages", mock.Anything).
				Return(errors.New("EC2.DescribeNetworkAclsPages error"))
		},
		"DescribeStaleSecurityGroupsPages": func(svc *MockEC2) {
			svc.On("DescribeStaleSecurityGroupsPages", mock.Anything).
				Return(errors.New("EC2.DescribeStaleSecurityGroupsPages error"))
		},
		"DescribeSnapshotsPages": func(svc *MockEC2) {
			svc.On("DescribeSnapshotsPages", mock.Anything).
				Return(errors.New("EC2.DescribeSnapshotsPages error"))
		},
		"DescribeImages": func(svc *MockEC2) {
			svc.On("DescribeImages", mock.Anything).
				Return(&ec2.DescribeImagesOutput{}, errors.New("EC2.DescribeImages error"))
		},
		"DescribeSnapshotAttribute": func(svc *MockEC2) {
			svc.On("DescribeSnapshotAttribute", mock.Anything).
				Return(&ec2.DescribeSnapshotAttributeOutput{},
					errors.New("EC2.DescribeSnapshotAttribute error"))
		},
		// Don't return error here as even in general error cases we want this to pass,
		// Testing for errors of this API call done explicitly
		"DescribeRegions": func(svc *MockEC2) {
			svc.On("DescribeRegions", mock.Anything).
				Return(ExampleDescribeRegionsOutput, nil)
		},
	}

	MockEC2ForSetup = &MockEC2{}
)

// EC2 mock

// SetupMockEC2 is used to override the EC2 Client initializer
func SetupMockEC2(_ *session.Session, _ *aws.Config) interface{} {
	return MockEC2ForSetup
}

// MockEC2 is a mock EC2 client
type MockEC2 struct {
	ec2iface.EC2API
	mock.Mock
}

// BuildMockEC2Svc builds and returns a MockEC2 struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockEC2Svc(funcs []string) (mockSvc *MockEC2) {
	mockSvc = &MockEC2{}
	for _, f := range funcs {
		svcEC2SetupCalls[f](mockSvc)
	}
	return
}

// BuildMockEC2SvcError builds and returns a MockEC2 struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockEC2SvcError(funcs []string) (mockSvc *MockEC2) {
	mockSvc = &MockEC2{}
	for _, f := range funcs {
		svcEC2SetupCallsError[f](mockSvc)
	}
	return
}

// BuildEC2ServiceSvcAll builds and returns a MockEC2 struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockEC2SvcAll() (mockSvc *MockEC2) {
	mockSvc = &MockEC2{}
	for _, f := range svcEC2SetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockEC2SvcAllError builds and returns a MockEC2 struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockEC2SvcAllError() (mockSvc *MockEC2) {
	mockSvc = &MockEC2{}
	for _, f := range svcEC2SetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockEC2) DescribeInstancesPages(
	in *ec2.DescribeInstancesInput,
	paginationFunction func(*ec2.DescribeInstancesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeInstancesOutput, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeVolumesPages(
	in *ec2.DescribeVolumesInput,
	paginationFunction func(*ec2.DescribeVolumesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeVolumesOutput, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeVpcsPages(
	in *ec2.DescribeVpcsInput,
	paginationFunction func(*ec2.DescribeVpcsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeVpcsOutput, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeFlowLogsPages(
	in *ec2.DescribeFlowLogsInput,
	paginationFunction func(*ec2.DescribeFlowLogsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeFlowLogsOutput, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeSecurityGroupsPages(
	in *ec2.DescribeSecurityGroupsInput,
	paginationFunction func(*ec2.DescribeSecurityGroupsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeSecurityGroupsOutput, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeSecurityGroups(in *ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*ec2.DescribeSecurityGroupsOutput), args.Error(1)
}

func (m *MockEC2) DescribeNetworkAclsPages(
	in *ec2.DescribeNetworkAclsInput,
	paginationFunction func(*ec2.DescribeNetworkAclsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeNetworkAclsOutput, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeNetworkAcls(in *ec2.DescribeNetworkAclsInput) (*ec2.DescribeNetworkAclsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*ec2.DescribeNetworkAclsOutput), args.Error(1)
}

func (m *MockEC2) DescribeRouteTablesPages(
	in *ec2.DescribeRouteTablesInput,
	paginationFunction func(*ec2.DescribeRouteTablesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeRouteTablesOutput, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeStaleSecurityGroupsPages(
	in *ec2.DescribeStaleSecurityGroupsInput,
	paginationFunction func(*ec2.DescribeStaleSecurityGroupsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeStaleSecurityGroups, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeSnapshotsPages(
	in *ec2.DescribeSnapshotsInput,
	paginationFunction func(*ec2.DescribeSnapshotsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleDescribeSnapshots, true)
	return args.Error(0)
}

func (m *MockEC2) DescribeRegions(in *ec2.DescribeRegionsInput) (*ec2.DescribeRegionsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*ec2.DescribeRegionsOutput), args.Error(1)
}

func (m *MockEC2) DescribeImages(in *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*ec2.DescribeImagesOutput), args.Error(1)
}

func (m *MockEC2) DescribeSnapshotAttribute(in *ec2.DescribeSnapshotAttributeInput) (*ec2.DescribeSnapshotAttributeOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*ec2.DescribeSnapshotAttributeOutput), args.Error(1)
}
