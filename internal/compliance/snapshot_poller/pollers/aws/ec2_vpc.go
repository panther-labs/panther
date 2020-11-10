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

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
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
		return nil, err
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
	vpc, err := getVPC(ec2Client, aws.String(vpcID))
	if err != nil {
		return nil, err
	}

	snapshot, err := buildEc2VpcSnapshot(ec2Client, vpc)
	if err != nil {
		return nil, err
	}
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
func getVPC(svc ec2iface.EC2API, vpcID *string) (*ec2.Vpc, error) {
	vpc, err := svc.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{vpcID},
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "InvalidVpcID.NotFound" {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *vpcID),
				zap.String("resourceType", awsmodels.Ec2VpcSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "EC2.DescribeVpcs: %s", aws.StringValue(vpcID))
	}
	if len(vpc.Vpcs) != 1 {
		return nil, errors.WithMessagef(
			errors.New("EC2.DescribeVpcs"),
			"expected exactly one VPC when describing %s, but found %d VPCs",
			aws.StringValue(vpcID),
			len(vpc.Vpcs),
		)
	}
	return vpc.Vpcs[0], nil
}

// describeRouteTables returns a list of all route tables for a given vpcID
func describeRouteTables(ec2Svc ec2iface.EC2API, vpcID *string) (routeTables []*ec2.RouteTable, err error) {
	err = ec2Svc.DescribeRouteTablesPages(
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
		return nil, errors.Wrapf(err, "EC2.DescribeRouteTablesPages: %s", aws.StringValue(vpcID))
	}
	return
}

// describeVpcs describes all VPCs for a given region
func describeVpcs(ec2Svc ec2iface.EC2API, nextMarker *string) (vpcs []*ec2.Vpc, marker *string, err error) {
	err = ec2Svc.DescribeVpcsPages(
		&ec2.DescribeVpcsInput{
			NextToken:  nextMarker,
			MaxResults: aws.Int64(int64(defaultBatchSize)),
		},
		func(page *ec2.DescribeVpcsOutput, lastPage bool) bool {
			return ec2VpcIterator(page, &vpcs, &marker)
		})

	if err != nil {
		return nil, nil, errors.Wrap(err, "EC2.DescribeVpcsPages")
	}
	return
}

func ec2VpcIterator(page *ec2.DescribeVpcsOutput, vpcs *[]*ec2.Vpc, marker **string) bool {
	*vpcs = append(*vpcs, page.Vpcs...)
	*marker = page.NextToken
	return len(*vpcs) < defaultBatchSize
}

// describeFlowLogs returns a list of flow logs associated to a given vpcID
func describeFlowLogs(ec2Svc ec2iface.EC2API, vpcID *string) (flowLogs []*ec2.FlowLog, err error) {
	err = ec2Svc.DescribeFlowLogsPages(
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
		return nil, errors.Wrapf(err, "EC2.DescribeFlowLogsPages: %s", aws.StringValue(vpcID))
	}
	return
}

// describeStaleSecurityGroups returns all the stale security groups for the given EC2 VPC
func describeStaleSecurityGroups(ec2Svc ec2iface.EC2API, vpcID *string) (staleSecurityGroups []*string, err error) {
	err = ec2Svc.DescribeStaleSecurityGroupsPages(
		&ec2.DescribeStaleSecurityGroupsInput{VpcId: vpcID},
		func(page *ec2.DescribeStaleSecurityGroupsOutput, lastPage bool) bool {
			for _, staleSecurityGroup := range page.StaleSecurityGroupSet {
				staleSecurityGroups = append(staleSecurityGroups, staleSecurityGroup.GroupId)
			}
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "EC2.DescribeStaleSecurityGroupsPages: %s", aws.StringValue(vpcID))
	}

	return
}

// describeSecurityGroupsVPC returns all the security groups for given VPC. Additionally, it returns the
// id of the default security group.
func describeSecurityGroupsVPC(svc ec2iface.EC2API, vpcID *string) (securityGroups []*string, defaultId *string, err error) {
	err = svc.DescribeSecurityGroupsPages(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{vpcID},
			},
		},
	}, func(page *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {
		for _, securityGroup := range page.SecurityGroups {
			securityGroups = append(securityGroups, securityGroup.GroupId)
			if aws.StringValue(securityGroup.GroupName) == "default" {
				defaultId = securityGroup.GroupId
			}
		}
		return true
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "EC2.DescribeSecurityGroups: %s", aws.StringValue(vpcID))
	}

	return
}

// describeNetworkACLsVPC returns all the network ACLs for given VPC. Additionally, it returns the
// id of the default network ACL.
func describeNetworkACLsVPC(svc ec2iface.EC2API, vpcID *string) (nacls []*string, defaultId *string, err error) {
	err = svc.DescribeNetworkAclsPages(&ec2.DescribeNetworkAclsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{vpcID},
			},
		},
	}, func(page *ec2.DescribeNetworkAclsOutput, lastPage bool) bool {
		for _, nacl := range page.NetworkAcls {
			nacls = append(nacls, nacl.NetworkAclId)
			if aws.BoolValue(nacl.IsDefault) {
				defaultId = nacl.NetworkAclId
			}
		}
		return true
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "EC2.DescribeNetworkAcls: %s", aws.StringValue(vpcID))
	}

	return
}

// buildEc2VpcSnapshot builds a full Ec2VpcSnapshot for a given EC2 VPC
func buildEc2VpcSnapshot(ec2Svc ec2iface.EC2API, vpc *ec2.Vpc) (*awsmodels.Ec2Vpc, error) {
	if vpc == nil {
		return nil, nil
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

	var err error
	if ec2Vpc.SecurityGroups, ec2Vpc.DefaultSecurityGroupId, err = describeSecurityGroupsVPC(ec2Svc, vpc.VpcId); err != nil {
		return nil, err
	}
	if ec2Vpc.NetworkAcls, ec2Vpc.DefaultNetworkAclId, err = describeNetworkACLsVPC(ec2Svc, vpc.VpcId); err != nil {
		return nil, err
	}
	if ec2Vpc.RouteTables, err = describeRouteTables(ec2Svc, vpc.VpcId); err != nil {
		return nil, err
	}
	if ec2Vpc.FlowLogs, err = describeFlowLogs(ec2Svc, vpc.VpcId); err != nil {
		return nil, err
	}
	if ec2Vpc.StaleSecurityGroups, err = describeStaleSecurityGroups(ec2Svc, vpc.VpcId); err != nil {
		return nil, err
	}

	return ec2Vpc, nil
}

// PollEc2Vpcs gathers information on each VPC in an AWS account.
func PollEc2Vpcs(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("building EC2 VPC snapshots", zap.String("region", *pollerInput.Region))
	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all VPCs
	vpcs, marker, err := describeVpcs(ec2Svc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// For each VPC, build out a full snapshot
	resources := make([]apimodels.AddResourceEntry, 0, len(vpcs))
	for _, vpc := range vpcs {
		ec2Vpc, err := buildEc2VpcSnapshot(ec2Svc, vpc)
		if err != nil {
			return nil, nil, err
		}

		// arn:aws:ec2:region:account-id:vpc/vpc-id
		resourceID := strings.Join(
			[]string{
				"arn",
				pollerInput.AuthSourceParsedARN.Partition,
				"ec2",
				*pollerInput.Region,
				*ec2Vpc.OwnerId,
				"vpc/" + *ec2Vpc.ID,
			},
			":",
		)
		// Populate generic fields
		ec2Vpc.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		ec2Vpc.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		ec2Vpc.Region = pollerInput.Region
		ec2Vpc.ARN = aws.String(resourceID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      ec2Vpc,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.Ec2VpcSchema,
		})
	}

	return resources, marker, nil
}
