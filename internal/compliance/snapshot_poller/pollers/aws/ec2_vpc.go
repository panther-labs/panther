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

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

var EC2ClientFunc = setupEC2Client

func setupEC2Client(sess *session.Session, cfg *aws.Config) interface{} {
	return ec2.New(sess, cfg)
}

func getEC2Client(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (ec2iface.EC2API, error) {
	client, err := getClient(pollerResourceInput, EC2ClientFunc, "ec2", region)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	return client.(ec2iface.EC2API), nil
}

// PollEC2VPC polls a single EC2 VPC resource
func PollEC2VPC(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	ec2Client, err := getEC2Client(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	vpcID := strings.Replace(resourceARN.Resource, "vpc/", "", 1)
	vpc := getVPC(ec2Client, aws.String(vpcID))

	snapshot := buildEc2VpcSnapshot(ec2Client, vpc)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getVPC returns a specific EC2 VPC
func getVPC(svc ec2iface.EC2API, vpcID *string) *ec2.Vpc {
	vpc, err := svc.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{vpcID},
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidVpcID.NotFound" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *vpcID),
					zap.String("resourceType", awsmodels.Ec2VpcSchema))
				return nil
			}
		}
		utils.LogAWSError("EC2.DescribeVpcs", err)
		return nil
	}
	return vpc.Vpcs[0]
}

// describeRouteTables returns a list of all route tables for a given vpcID
func describeRouteTables(ec2Svc ec2iface.EC2API, vpcID *string) (routeTables []*ec2.RouteTable) {
	err := ec2Svc.DescribeRouteTablesPages(
		&ec2.DescribeRouteTablesInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String("resource-id"),
					Values: []*string{vpcID},
				},
			},
		},
		func(page *ec2.DescribeRouteTablesOutput, lastPage bool) bool {
			routeTables = append(routeTables, page.RouteTables...)
			return true
		})

	if err != nil {
		utils.LogAWSError("EC2.DescribeRouteTablesPages", err)
		return nil
	}
	return
}

// describeVpcs describes all VPCs for a given region
func describeVpcs(ec2Svc ec2iface.EC2API) (vpcs []*ec2.Vpc, err error) {
	err = ec2Svc.DescribeVpcsPages(
		&ec2.DescribeVpcsInput{},
		func(page *ec2.DescribeVpcsOutput, lastPage bool) bool {
			vpcs = append(vpcs, page.Vpcs...)
			return true
		})

	if err != nil {
		return nil, errors.Wrap(err, "EC2.DescribeVpcsPages")
	}
	return
}

// describeFlowLogs returns a list of flow logs associated to a given vpcID
func describeFlowLogs(ec2Svc ec2iface.EC2API, vpcID *string) (flowLogs []*ec2.FlowLog) {
	err := ec2Svc.DescribeFlowLogsPages(
		&ec2.DescribeFlowLogsInput{
			Filter: []*ec2.Filter{
				{
					Name:   aws.String("resource-id"),
					Values: []*string{vpcID},
				},
			},
		},
		func(page *ec2.DescribeFlowLogsOutput, lastPage bool) bool {
			flowLogs = append(flowLogs, page.FlowLogs...)
			return true
		})

	if err != nil {
		utils.LogAWSError("EC2.DescribeFlowLogsPages", err)
		return nil
	}
	return
}

// describeStaleSecurityGroups returns all the stale security groups for the given EC2 VPC
func describeStaleSecurityGroups(ec2Svc ec2iface.EC2API, vpcID *string) []*ec2.StaleSecurityGroup {
	var result []*ec2.StaleSecurityGroup
	err := ec2Svc.DescribeStaleSecurityGroupsPages(
		&ec2.DescribeStaleSecurityGroupsInput{VpcId: vpcID},
		func(page *ec2.DescribeStaleSecurityGroupsOutput, lastPage bool) bool {
			result = append(result, page.StaleSecurityGroupSet...)
			return true
		})

	if err != nil {
		utils.LogAWSError("EC2.DescribeStaleSecurityGroupsPages", err)
		return nil
	}

	return result
}

// describeSecurityGroupsVPC returns all the security groups for given VPC
func describeSecurityGroupsVPC(svc ec2iface.EC2API, vpcID *string) []*ec2.SecurityGroup {
	securityGroups, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{vpcID},
			},
		},
	})
	if err != nil {
		utils.LogAWSError("EC2.DescribeSecurityGroups", err)
		return nil
	}
	return securityGroups.SecurityGroups
}

// describeNetworkACLsVPC returns all the network ACLs for given VPC
func describeNetworkACLsVPC(svc ec2iface.EC2API, vpcID *string) []*ec2.NetworkAcl {
	networkACLs, err := svc.DescribeNetworkAcls(&ec2.DescribeNetworkAclsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{vpcID},
			},
		},
	})
	if err != nil {
		utils.LogAWSError("EC2.DescribeNetworkAcls", err)
		return nil
	}
	return networkACLs.NetworkAcls
}

// buildEc2VpcSnapshot builds a full Ec2VpcSnapshot for a given EC2 VPC
func buildEc2VpcSnapshot(ec2Svc ec2iface.EC2API, vpc *ec2.Vpc) *awsmodels.Ec2Vpc {
	if vpc == nil {
		return nil
	}
	ec2Vpc := &awsmodels.Ec2Vpc{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.Ec2VpcSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ID:   vpc.VpcId,
			Tags: utils.ParseTagSlice(vpc.Tags),
		},

		CidrBlock:                   vpc.CidrBlock,
		CidrBlockAssociationSet:     vpc.CidrBlockAssociationSet,
		DhcpOptionsId:               vpc.DhcpOptionsId,
		InstanceTenancy:             vpc.InstanceTenancy,
		Ipv6CidrBlockAssociationSet: vpc.Ipv6CidrBlockAssociationSet,
		IsDefault:                   vpc.IsDefault,
		OwnerId:                     vpc.OwnerId,
		State:                       vpc.State,
	}

	ec2Vpc.SecurityGroups = describeSecurityGroupsVPC(ec2Svc, vpc.VpcId)
	ec2Vpc.NetworkAcls = describeNetworkACLsVPC(ec2Svc, vpc.VpcId)
	ec2Vpc.RouteTables = describeRouteTables(ec2Svc, vpc.VpcId)
	ec2Vpc.FlowLogs = describeFlowLogs(ec2Svc, vpc.VpcId)
	ec2Vpc.StaleSecurityGroups = describeStaleSecurityGroups(ec2Svc, vpc.VpcId)

	return ec2Vpc
}

// PollEc2Vpcs gathers information on each VPC in an AWS account.
func PollEc2Vpcs(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting EC2 VPC resource poller")
	ec2VpcSnapshots := make(map[string]*awsmodels.Ec2Vpc)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "ec2") {
		zap.L().Debug("building EC2 VPC snapshots", zap.String("region", *regionID))
		ec2Svc, err := getEC2Client(pollerInput, *regionID)
		if err != nil {
			return nil, err // error is logged in getClient()
		}

		// Start with generating a list of all VPCs
		vpcs, err := describeVpcs(ec2Svc)
		if err != nil {
			return nil, errors.Wrapf(err, "PollEc2Vpcs(%#v) in region %s", *pollerInput, *regionID)
		}
		if len(vpcs) == 0 {
			zap.L().Debug("no EC2 VPCs found", zap.String("region", *regionID))
			continue
		}

		// For each VPC, build out a full snapshot
		for _, vpc := range vpcs {
			ec2Vpc := buildEc2VpcSnapshot(ec2Svc, vpc)

			// arn:aws:ec2:region:account-id:vpc/vpc-id
			resourceID := strings.Join(
				[]string{
					"arn",
					pollerInput.AuthSourceParsedARN.Partition,
					"ec2",
					*regionID,
					*ec2Vpc.OwnerId,
					"vpc/" + *ec2Vpc.ID,
				},
				":",
			)
			// Populate generic fields
			ec2Vpc.ResourceID = aws.String(resourceID)

			// Populate AWS generic fields
			ec2Vpc.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			ec2Vpc.Region = regionID
			ec2Vpc.ARN = aws.String(resourceID)

			if _, ok := ec2VpcSnapshots[resourceID]; !ok {
				ec2VpcSnapshots[resourceID] = ec2Vpc
			} else {
				zap.L().Info("overwriting existing EC2 VPC snapshot", zap.String("resourceId", resourceID))
				ec2VpcSnapshots[resourceID] = ec2Vpc
			}
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(ec2VpcSnapshots))
	for resourceID, ec2VpcSnapshot := range ec2VpcSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      ec2VpcSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.Ec2VpcSchema,
		})
	}

	return resources, nil
}
