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
	Ec2AmiSchema = "AWS.EC2.AMI"
)

// Ec2Ami contains all information about an EC2 AMI
type Ec2Ami struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from ec2.Image
	Architecture        *string
	BlockDeviceMappings []*ec2.BlockDeviceMapping
	Description         *string
	EnaSupport          *bool
	Hypervisor          *string
	ImageLocation       *string
	ImageOwnerAlias     *string
	ImageType           *string
	KernelId            *string
	OwnerId             *string
	Platform            *string
	ProductCodes        []*ec2.ProductCode
	Public              *bool
	RamdiskId           *string
	RootDeviceName      *string
	RootDeviceType      *string
	SriovNetSupport     *string
	State               *string
	StateReason         *ec2.StateReason
	VirtualizationType  *string
}
