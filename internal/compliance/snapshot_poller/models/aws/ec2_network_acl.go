package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	Ec2NetworkAclSchema = "AWS.EC2.NetworkACL"
)

// Ec2NetworkACL contains all information about an EC2 Network ACL
type Ec2NetworkAcl struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from ec2.NetworkAcl
	Associations []*ec2.NetworkAclAssociation
	Entries      []*ec2.NetworkAclEntry
	IsDefault    *bool
	OwnerId      *string
	VpcId        *string
}
