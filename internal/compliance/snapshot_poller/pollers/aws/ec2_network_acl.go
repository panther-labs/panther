package aws

/**
 * A Cloud-Native SIEM for the Modern Security Team
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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// PollEC2NetworkACL polls a single EC2 Network ACL resource
func PollEC2NetworkACL(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	ec2Client, err := getEC2Client(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	naclID := strings.Replace(resourceARN.Resource, "network-acl/", "", 1)
	nacl := getNetworkACL(ec2Client, aws.String(naclID))

	snapshot := buildEc2NetworkAclSnapshot(ec2Client, nacl)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getNetworkACL returns a specific EC2 network ACL
func getNetworkACL(svc ec2iface.EC2API, networkACLID *string) *ec2.NetworkAcl {
	nacl, err := svc.DescribeNetworkAcls(&ec2.DescribeNetworkAclsInput{
		NetworkAclIds: []*string{networkACLID},
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidNetworkAclID.NotFound" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *networkACLID),
					zap.String("resourceType", awsmodels.Ec2NetworkAclSchema))
				return nil
			}
		}
		utils.LogAWSError("EC2.DescribeNetworkACLs", err)
		return nil
	}

	return nacl.NetworkAcls[0]
}

// describeNetworkAclsPages returns all Network ACLs for a given region
func describeNetworkAcls(ec2Svc ec2iface.EC2API) (networkACLs []*ec2.NetworkAcl) {
	err := ec2Svc.DescribeNetworkAclsPages(&ec2.DescribeNetworkAclsInput{},
		func(page *ec2.DescribeNetworkAclsOutput, lastPage bool) bool {
			networkACLs = append(networkACLs, page.NetworkAcls...)
			return true
		})

	if err != nil {
		utils.LogAWSError("EC2.DescribeNetworkAclsPages", err)
	}
	return
}

func buildEc2NetworkAclSnapshot(_ ec2iface.EC2API, networkACL *ec2.NetworkAcl) *awsmodels.Ec2NetworkAcl {
	if networkACL == nil {
		return nil
	}
	ec2NetworkACLSnapshot := &awsmodels.Ec2NetworkAcl{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.Ec2NetworkAclSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ID:   networkACL.NetworkAclId,
			Tags: utils.ParseTagSlice(networkACL.Tags),
		},
		Associations: networkACL.Associations,
		Entries:      networkACL.Entries,
		IsDefault:    networkACL.IsDefault,
		OwnerId:      networkACL.OwnerId,
		VpcId:        networkACL.VpcId,
	}
	return ec2NetworkACLSnapshot
}

// PollEc2NetworkAcls gathers information on each Network ACL in an AWS account.
func PollEc2NetworkAcls(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting EC2 Network ACL resource poller")
	ec2NetworkACLSnapshots := make(map[string]*awsmodels.Ec2NetworkAcl)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "ec2") {
		ec2Svc, err := getEC2Client(pollerInput, *regionID)
		if err != nil {
			return nil, err // error is logged in getClient()
		}

		// Start with generating a list of all Network ACLs
		networkACLs := describeNetworkAcls(ec2Svc)
		if len(networkACLs) == 0 {
			zap.L().Debug("no EC2 Network ACLs found", zap.String("region", *regionID))
			continue
		}

		// For each Network ACL, build out a full snapshot
		for _, networkACL := range networkACLs {
			ec2NetworkACLSnapshot := buildEc2NetworkAclSnapshot(ec2Svc, networkACL)

			// arn:aws:ec2:region:account-id:network-acl/nacl-id
			resourceID := strings.Join(
				[]string{
					"arn",
					pollerInput.AuthSourceParsedARN.Partition,
					"ec2",
					*regionID,
					*ec2NetworkACLSnapshot.OwnerId,
					"network-acl/" + *ec2NetworkACLSnapshot.ID,
				},
				":",
			)

			// Populate generic fields
			ec2NetworkACLSnapshot.ResourceID = aws.String(resourceID)

			// Populate AWS generic fields
			ec2NetworkACLSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			ec2NetworkACLSnapshot.Region = regionID
			ec2NetworkACLSnapshot.ARN = aws.String(resourceID)

			if _, ok := ec2NetworkACLSnapshots[resourceID]; !ok {
				ec2NetworkACLSnapshots[resourceID] = ec2NetworkACLSnapshot
			} else {
				zap.L().Info("overwriting existing EC2 Network ACL snapshot",
					zap.String("resourceId", resourceID))
				ec2NetworkACLSnapshots[resourceID] = ec2NetworkACLSnapshot
			}
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(ec2NetworkACLSnapshots))
	for resourceID, ec2NetworkACLSnapshot := range ec2NetworkACLSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      ec2NetworkACLSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.Ec2NetworkAclSchema,
		})
	}

	return resources, nil
}
