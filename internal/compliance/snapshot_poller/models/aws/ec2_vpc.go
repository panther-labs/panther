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
	Ec2VpcSchema = "AWS.EC2.VPC"
)

// Ec2Vpc contains all information about an EC2 VPC
type Ec2Vpc struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from ec2.Vpc
	CidrBlock                   *string
	CidrBlockAssociationSet     []*ec2.VpcCidrBlockAssociation
	DhcpOptionsId               *string
	InstanceTenancy             *string
	Ipv6CidrBlockAssociationSet []*ec2.VpcIpv6CidrBlockAssociation
	IsDefault                   *bool
	OwnerId                     *string
	State                       *string

	// Additional fields
	DefaultSecurityGroupId *string
	DefaultNetworkAclId    *string
	FlowLogs               []*ec2.FlowLog
	NetworkAcls            []*string
	RouteTables            []*ec2.RouteTable
	SecurityGroups         []*string
	StaleSecurityGroups    []*string
}
