package processor

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
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyEC2(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonec2.html

	// arn:aws:ec2:region:account-id:resource-type/resource-id
	ec2ARN := arn.ARN{
		Partition: "aws",
		Service:   "ec2",
		Region:    metadata.region,
		AccountID: metadata.accountID,
	}

	var ec2Type string
	var deleteResource bool
	switch metadata.eventName {
	case "AssociateAddress", "ModifyInstanceAttribute", "AttachNetworkInterface",
		"ModifyInstanceCapacityReservationAttributes", "ModifyInstanceCreditSpecificationResponse", "ResetInstanceAttribute":
		// Generic EC2 Instance event request handler
		ec2Type = aws.Ec2InstanceSchema
		ec2ARN.Resource = "instance/" + detail.Get("requestParameters.instanceId").Str
	case "CreateNetworkAclEntry", "DeleteNetworkAclEntry", "ReplaceNetworkAclAssociation", "ReplaceNetworkAclEntry":
		// Generic EC2 Network ACL request handler
		ec2Type = aws.Ec2NetworkAclSchema
		ec2ARN.Resource = "network-acl/" + detail.Get("requestParameters.networkAclId").Str
	case "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress":
		// Generic EC2 Security Group request handler
		ec2Type = aws.Ec2SecurityGroupSchema
		ec2ARN.Resource = "security-group/" + detail.Get("requestParameters.groupId").Str
	case "CreateRouteTable", "AttachInternetGateway", "CreateSubnet", "AssociateDhcpOptions", "ModifyVpcAttribute", "ModifyVpcTenancy":
		// Generic EC2 VPC request handler
		ec2Type = aws.Ec2VpcSchema
		ec2ARN.Resource = "vpc/" + detail.Get("requestParameters.vpcId").Str
	case "CreateSnapshot", "ModifyVolume", "ModifyVolumeAttribute":
		// Generic EC2 Volume handler
		ec2Type = aws.Ec2VolumeSchema
		ec2ARN.Resource = "volume/" + detail.Get("requestParameters.volumeId").Str
	case "ModifyImageAttribute", "ResetImageAttribute":
		// Generic EC2 Image handler
		ec2Type = aws.Ec2AmiSchema
		ec2ARN.Resource = "image/" + detail.Get("requestParameters.imageId").Str
	case "AttachVolume":
		return []*resourceChange{
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "instance/" + detail.Get("requestParameters.instanceId").Str,
				ResourceType: aws.Ec2InstanceSchema,
			},
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "volume/" + detail.Get("requestParameters.volumeId").Str,
				ResourceType: aws.Ec2VolumeSchema,
			},
		}
	case "ModifyInstanceCreditSpecification":
		var instancesChanged []*resourceChange
		for _, instance := range detail.Get("responseElements.ModifyInstanceCreditSpecificationResponse.items").Array() {
			instancesChanged = append(instancesChanged, &resourceChange{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "instance/" + instance.Get("instanceId").Str,
				ResourceType: aws.Ec2InstanceSchema,
			})
		}
		return instancesChanged
	case "DeleteSecurityGroup":
		deleteResource = true
		ec2Type = aws.Ec2SecurityGroupSchema
		ec2ARN.Resource = "security-group/" + detail.Get("requestParameters.groupId").Str
	case "DeleteVpc":
		deleteResource = true
		ec2Type = aws.Ec2VpcSchema
		ec2ARN.Resource = "vpc/" + detail.Get("requestParameters.vpcId").Str
	case "DeleteNetworkAcl":
		deleteResource = true
		ec2Type = aws.Ec2NetworkAclSchema
		ec2ARN.Resource = "network-acl/" + detail.Get("requestParameters.networkAclId").Str
	case "DeleteVolume":
		deleteResource = true
		ec2Type = aws.Ec2VolumeSchema
		ec2ARN.Resource = "volume/" + detail.Get("requestParameters.volumeId").Str
	case "TerminateInstances":
		// Similar to MonitorInstances, except that we will also mark these resources for deletion
		var instancesChanged []*resourceChange
		for _, instance := range detail.Get("requestParameters.instancesSet.items").Array() {
			instancesChanged = append(instancesChanged, &resourceChange{
				AwsAccountID: metadata.accountID,
				Delete:       true,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "instance/" + instance.Get("instanceId").Str,
				ResourceType: aws.Ec2InstanceSchema,
			})
		}
		return instancesChanged
	case "CreateFlowLogs":
		ec2Type = aws.Ec2VpcSchema
		ec2ARN.Resource = "vpc/" + detail.Get("requestParameters.CreateFlowLogsRequest.ResourceId.content").Str
	case "CreateNetworkAcl":
		// This creates a new network ACL resource which we need to scan, and modifies an existing
		// VPC resource by adding the network ACL (which is not embedded, but its ARN is referenced)
		return []*resourceChange{
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "vpc/" + detail.Get("responseElements.networkAcl.vpcId").Str,
				ResourceType: aws.Ec2VpcSchema,
			},
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "network-acl/" + detail.Get("responseElements.networkAcl.networkAclId").Str,
				ResourceType: aws.Ec2NetworkAclSchema,
			},
		}
	case "AssociateIamInstanceProfile":
		ec2Type = aws.Ec2InstanceSchema
		ec2ARN.Resource = "instance/" + detail.Get("requestParameters.AssociateIamInstanceProfileRequest.InstanceId").Str
	case "AcceptVpcPeeringConnection":
		// This potentially effects two VPCs in the same account, return them both and if one is in
		// another account it will be thrown out later
		peeringRequester := detail.Get("responseElements.vpcPeeringConnection.requesterVpcInfo")
		peeringAccepter := detail.Get("responseElements.vpcPeeringConnection.accepterVpcInfo")
		// arn:aws:ec2:region:account-id:vpc/vpc-id
		requesterARN := strings.Join([]string{
			"arn:aws:ec2",
			peeringRequester.Get("region").Str,
			peeringRequester.Get("ownerId").Str,
			"vpc/" + peeringRequester.Get("vpcId").Str,
		}, ":")
		accepterARN := strings.Join([]string{
			"arn:aws:ec2",
			peeringAccepter.Get("region").Str,
			peeringAccepter.Get("ownerId").Str,
			"vpc/" + peeringAccepter.Get("vpcId").Str,
		}, ":")
		return []*resourceChange{
			{
				AwsAccountID: peeringRequester.Get("ownerId").Str,
				EventName:    "AcceptVpcPeeringConnection",
				ResourceID:   requesterARN,
				ResourceType: aws.Ec2VpcSchema,
			},
			{
				AwsAccountID: peeringAccepter.Get("ownerId").Str,
				EventName:    "AcceptVpcPeeringConnection",
				ResourceID:   accepterARN,
				ResourceType: aws.Ec2VpcSchema,
			},
		}
	case "AssociateVpcCidrBlock":
		ec2Type = aws.Ec2VpcSchema
		ec2ARN.Resource = "vpc/" + detail.Get("requestParameters.AssociateVpcCidrBlockRequest.VpcId").Str
	case "DisassociateVpcCidrBlock":
		ec2Type = aws.Ec2VpcSchema
		ec2ARN.Resource = "vpc/" + detail.Get("responseElements.DisassociateVpcCidrBlockResponse.vpcId").Str
	case "CreateSecurityGroup":
		// Same situation as CreateNetworkAcl
		return []*resourceChange{
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "vpc/" + detail.Get("requestParameters.vpcId").Str,
				ResourceType: aws.Ec2VpcSchema,
			},
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "security-group/" + detail.Get("responseElements.groupId").Str,
				ResourceType: aws.Ec2SecurityGroupSchema,
			},
		}
	case "CreateTags", "DeleteTags":
		// This case is particularly problematic because its one API call that can modify any EC2
		// resource, so we first have to determine which resource type is being modified so we can
		// set type/ARN/resourceID appropriately. Additionally, its possible for multiple resources
		// to be modified in one invocation of this API.
		var changes []*resourceChange
		for _, resource := range detail.Get("requestParameters.resourcesSet.items").Array() {
			id := resource.Get("resourceId").Str
			var resourceType string
			var resourceID string
			switch {
			case strings.HasPrefix(id, "image-"):
				resourceType = aws.Ec2AmiSchema
				resourceID = "image/" + id
			case strings.HasPrefix(id, "instance-") || strings.HasPrefix(id, "i-"):
				resourceType = aws.Ec2InstanceSchema
				resourceID = "instance/" + id
			case strings.HasPrefix(id, "acl-"):
				resourceType = aws.Ec2NetworkAclSchema
				resourceID = "network-acl/" + id
			case strings.HasPrefix(id, "sg-"):
				resourceType = aws.Ec2SecurityGroupSchema
				resourceID = "security-group/" + id
			case strings.HasPrefix(id, "volume-"):
				resourceType = aws.Ec2VolumeSchema
				resourceID = "volume/" + id
			case strings.HasPrefix(id, "vpc-"):
				resourceType = aws.Ec2VpcSchema
				resourceID = "vpc/" + id
			default:
				zap.L().Debug("ec2: unsupported resource", zap.String("AWS resourceID", id))
				continue
			}
			changes = append(changes, &resourceChange{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + resourceID,
				ResourceType: resourceType,
			})
		}
		return changes
	case "CreateVolume":
		ec2Type = aws.Ec2VolumeSchema
		ec2ARN.Resource = "volume/" + detail.Get("responseElements.volumeId").Str
	case "CreateVpc":
		ec2Type = aws.Ec2VpcSchema
		// Not using the ec2ARN variable here because we have a better indicator of accountID
		ec2ARN.AccountID = detail.Get("responseElements.vpc.ownerId").Str
		ec2ARN.Resource = "vpc/" + detail.Get("responseElements.vpc.vpcId").Str
	case "CreateDefaultSubnet":
		ec2Type = aws.Ec2VpcSchema
		ec2ARN.Resource = "vpc/" + detail.Get("responseElements.subnet.vpcId").Str
	case "CreateDefaultVpc":
		ec2Type = aws.Ec2VpcSchema
		ec2ARN.Resource = "vpc/" + detail.Get("responseElements.vpc.vpcId").Str
	case "DetachVolume":
		return []*resourceChange{
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "instance/" + detail.Get("requestParameters.instanceId").Str,
				ResourceType: aws.Ec2InstanceSchema,
			},
			{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "volume/" + detail.Get("requestParameters.volumeId").Str,
				ResourceType: aws.Ec2VolumeSchema,
			},
		}
	case "ImportImage":
		ec2Type = aws.Ec2AmiSchema
		ec2ARN.Resource = "image/" + detail.Get("responseElements.imageId").Str
	case "ImportInstance":
		ec2Type = aws.Ec2InstanceSchema
		ec2ARN.Resource = "instance/" + detail.Get("responseElements.conversionTask.instanceId").Str
	case "ImportVolume":
		ec2Type = aws.Ec2VolumeSchema
		ec2ARN.Resource = "volume/" + detail.Get("responseElements.conversionTask.volume.id").Str
	case "MonitorInstances", "UnmonitorInstances", "StartInstances", "StopInstances":
		// Similar to CreateTags, except that it will only apply to instances
		var instancesChanged []*resourceChange
		for _, instance := range detail.Get("requestParameters.instancesSet.items").Array() {
			instancesChanged = append(instancesChanged, &resourceChange{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   ec2ARN.String() + "instance/" + instance.Get("instanceId").Str,
				ResourceType: aws.Ec2InstanceSchema,
			})
		}
		return instancesChanged
	case "RunInstances", "RunScheduledInstances":
		// Similar to MonitorInstances, except we actually know the owner
		var instancesChanged []*resourceChange
		for _, instance := range detail.Get("responseElements.instancesSet.items").Array() {
			instancesChanged = append(instancesChanged, &resourceChange{
				AwsAccountID: detail.Get("responseElements.ownerId").Str,
				EventName:    metadata.eventName,
				ResourceID: strings.Join([]string{
					"arn:aws:ec2",
					metadata.region,
					detail.Get("responseElements.ownerId").Str,
					"instance/" + instance.Get("instanceId").Str,
				}, ":"),
				ResourceType: aws.Ec2InstanceSchema,
			})
		}
		return instancesChanged
	case "UpdateSecurityGroupRuleDescriptionsEgress", "UpdateSecurityGroupRuleDescriptionsIngress":
		ec2Type = aws.Ec2SecurityGroupSchema
		if id := detail.Get("requestParameters.groupId").Str; id != "" {
			ec2ARN.Resource = "security-group/" + id
			break
		}
		// For the default VPC only, the security group name may be specified instead of the security
		// group ID. In that case, we have no way to identify the security group and must do a full
		// security group scan.
		return []*resourceChange{{
			AwsAccountID: ec2ARN.AccountID,
			Delete:       false,
			EventName:    metadata.eventName,
			Region:       metadata.region,
			ResourceType: ec2Type,
		}}
	case "DisassociateRouteTable", "AssociateRouteTable", "DeleteRouteTable", "ReplaceRoute", "CreateRoute",
		"DeleteRoute", "AssociateSubnetCidrBlock", "DeleteSubnet", "DisassociateSubnetCidrBlock", "ModifySubnetAttribute",
		"ModifyVpcPeeringConnectionOptions", "DeleteFlowLogs", "CreateNetworkInterface", "ReplaceRouteTableAssociation":
		// These resources are currently sub-resources to other full resources in our internal
		// representation of them, so we need to scan the full account to figure out which parent
		// resource changed. We can fix this by either creating a full resource for these and allowing
		// the parent resource to refer to them by resourceID, or by creating a link table.
		//
		// VPC Sub resources
		return []*resourceChange{{
			AwsAccountID: ec2ARN.AccountID,
			Delete:       false,
			EventName:    metadata.eventName,
			Region:       metadata.region,
			ResourceType: aws.Ec2VpcSchema,
		}}
	case "DeleteSnapshot", "ModifySnapshotAttribute":
		// Volume sub resources
		return []*resourceChange{{
			AwsAccountID: ec2ARN.AccountID,
			Delete:       false,
			EventName:    metadata.eventName,
			Region:       metadata.region,
			ResourceType: aws.Ec2VolumeSchema,
		}}
	case "DetachNetworkInterface":
		// Instance sub resources
		return []*resourceChange{{
			AwsAccountID: ec2ARN.AccountID,
			Delete:       false,
			EventName:    metadata.eventName,
			Region:       metadata.region,
			ResourceType: aws.Ec2InstanceSchema,
		}}
	case "ReplaceIamInstanceProfileAssociation":
		ec2Type = aws.Ec2InstanceSchema
		ec2ARN.Resource = "instance/" + detail.Get("responseElements.iamInstanceProfileAssociation.instanceId").Str
	case "DisassociateAddress":
		// This can effect either an EC2 VPC or an EC2 Instance Classic
		associationID := detail.Get("requestParameters.associationId").Str
		if associationID != "" {
			// This case means this is an EC2 VPC Address request. This is an EC2 VPC sub-resource
			// currently so we do a region wide EC2 VPC scan.
			return []*resourceChange{{
				AwsAccountID: ec2ARN.AccountID,
				Delete:       false,
				EventName:    metadata.eventName,
				Region:       metadata.region,
				ResourceType: aws.Ec2VpcSchema,
			}}
		}
		// This is an EC2 classic address request. We do not currently support EC2 classic instances
		return nil
	case "DeleteVpcPeeringConnection":
		// This could effect any two VPCs in the account in any region, so we must do an account wide
		// EC2 VPC scan.
		return []*resourceChange{{
			AwsAccountID: ec2ARN.AccountID,
			Delete:       false,
			EventName:    metadata.eventName,
			ResourceType: aws.Ec2VpcSchema,
		}}
	default:
		zap.L().Debug("ec2: unknown API call, making a guess...")
		// Give it the old college try, grabbing a bad resource ID here is a minor overhead for the
		// poller and should impose no risk. We can review the correct guesses in the logs and add
		// them to the right place as appropriate.
		if id := detail.Get("*.instanceId").Str; id != "" {
			ec2Type = aws.Ec2InstanceSchema
			ec2ARN.Resource = "instance/" + id
			break
		}
		if id := detail.Get("*.networkAclId").Str; id != "" {
			ec2Type = aws.Ec2NetworkAclSchema
			ec2ARN.Resource = "network-acl/" + id
			break
		}
		if id := detail.Get("*.groupId").Str; id != "" {
			ec2Type = aws.Ec2SecurityGroupSchema
			ec2ARN.Resource = "security-group/" + id
			break
		}
		if id := detail.Get("*.volumeId").Str; id != "" {
			ec2Type = aws.Ec2VolumeSchema
			ec2ARN.Resource = "volume/" + id
			break
		}
		if id := detail.Get("*.vpcId").Str; id != "" {
			ec2Type = aws.Ec2VpcSchema
			ec2ARN.Resource = "vpc/" + id
			break
		}
		zap.L().Info("ec2: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: ec2ARN.AccountID,
		Delete:       deleteResource,
		EventName:    metadata.eventName,
		ResourceID:   ec2ARN.String(),
		ResourceType: ec2Type,
	}}
}
