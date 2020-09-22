package aws

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

import "github.com/aws/aws-sdk-go/service/ec2"

const (
	Ec2InstanceSchema = "AWS.EC2.Instance"
)

// Ec2Instance contains all information about an EC2 Instance
type Ec2Instance struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from ec2.Instance
	AmiLaunchIndex                          *int64
	Architecture                            *string
	BlockDeviceMappings                     []*ec2.InstanceBlockDeviceMapping
	CapacityReservationId                   *string
	CapacityReservationSpecification        *ec2.CapacityReservationSpecificationResponse
	ClientToken                             *string
	CpuOptions                              *ec2.CpuOptions
	EbsOptimized                            *bool
	ElasticGpuAssociations                  []*ec2.ElasticGpuAssociation
	ElasticInferenceAcceleratorAssociations []*ec2.ElasticInferenceAcceleratorAssociation
	EnaSupport                              *bool
	HibernationOptions                      *ec2.HibernationOptions
	Hypervisor                              *string
	IamInstanceProfile                      *ec2.IamInstanceProfile
	ImageId                                 *string
	InstanceLifecycle                       *string
	InstanceType                            *string
	KernelId                                *string
	KeyName                                 *string
	Licenses                                []*ec2.LicenseConfiguration
	MetadataOptions                         *ec2.InstanceMetadataOptionsResponse
	Monitoring                              *ec2.Monitoring
	NetworkInterfaces                       []*ec2.InstanceNetworkInterface
	Placement                               *ec2.Placement
	Platform                                *string
	PrivateDnsName                          *string
	PrivateIpAddress                        *string
	ProductCodes                            []*ec2.ProductCode
	PublicDnsName                           *string
	PublicIpAddress                         *string
	RamdiskId                               *string
	RootDeviceName                          *string
	RootDeviceType                          *string
	SecurityGroups                          []*ec2.GroupIdentifier
	SourceDestCheck                         *bool
	SpotInstanceRequestId                   *string
	SriovNetSupport                         *string
	State                                   *ec2.InstanceState
	StateReason                             *ec2.StateReason
	StateTransitionReason                   *string
	SubnetId                                *string
	VirtualizationType                      *string
	VpcId                                   *string
}
