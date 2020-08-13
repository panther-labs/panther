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
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// PollEC2SecurityGroup polls a single EC2 Security Group resource
func PollEC2SecurityGroup(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	ec2Client, err := getEC2Client(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	sgID := strings.Replace(resourceARN.Resource, "security-group/", "", 1)
	securityGroup := getSecurityGroup(ec2Client, aws.String(sgID))

	snapshot := buildEc2SecurityGroupSnapshot(ec2Client, securityGroup)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ARN = scanRequest.ResourceID
	return snapshot, nil
}

// getSecurityGroup returns a specific EC2 security group
func getSecurityGroup(svc ec2iface.EC2API, securityGroupID *string) *ec2.SecurityGroup {
	securityGroup, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{securityGroupID},
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidGroup.NotFound" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *securityGroupID),
					zap.String("resourceType", awsmodels.Ec2SecurityGroupSchema))
				return nil
			}
		}
		utils.LogAWSError("EC2.DescribeSecurityGroups", err)
		return nil
	}

	return securityGroup.SecurityGroups[0]
}

// describeSecurityGroupsPages returns all Security Groups for a given region
func describeSecurityGroups(ec2Svc ec2iface.EC2API, nextMarker *string) (securityGroups []*ec2.SecurityGroup, marker *string) {
	err := ec2Svc.DescribeSecurityGroupsPages(&ec2.DescribeSecurityGroupsInput{
		NextToken: nextMarker,
	},
		func(page *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {
			securityGroups = append(securityGroups, page.SecurityGroups...)
			if len(securityGroups) >= defaultBatchSize {
				if !lastPage {
					marker = page.NextToken
				}
				return false
			}
			return true
		})

	if err != nil {
		utils.LogAWSError("EC2.DescribeSecurityGroupsPages", err)
	}
	return
}

func buildEc2SecurityGroupSnapshot(_ ec2iface.EC2API, securityGroup *ec2.SecurityGroup) *awsmodels.Ec2SecurityGroup {
	if securityGroup == nil {
		return nil
	}
	ec2SecurityGroupSnapshot := &awsmodels.Ec2SecurityGroup{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.Ec2SecurityGroupSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name: securityGroup.GroupName,
			ID:   securityGroup.GroupId,
			Tags: utils.ParseTagSlice(securityGroup.Tags),
		},
		Description:         securityGroup.Description,
		IpPermissions:       securityGroup.IpPermissions,
		IpPermissionsEgress: securityGroup.IpPermissionsEgress,
		OwnerId:             securityGroup.OwnerId,
		VpcId:               securityGroup.VpcId,
	}

	return ec2SecurityGroupSnapshot
}

// PollEc2SecurityGroups gathers information on each Security Group in an AWS account.
func PollEc2SecurityGroups(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 Security Group resource poller")
	ec2SecurityGroupSnapshots := make(map[string]*awsmodels.Ec2SecurityGroup)

	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err // error is logged in getClient()
	}

	// Start with generating a list of all Security Groups
	securityGroups, marker := describeSecurityGroups(ec2Svc, pollerInput.NextPageToken)
	if len(securityGroups) == 0 {
		zap.L().Debug("no EC2 Security Groups found", zap.String("region", *pollerInput.Region))
		return nil, nil, nil
	}

	// For each Security Group, build out a full snapshot
	for _, securityGroup := range securityGroups {
		ec2SecurityGroupSnapshot := buildEc2SecurityGroupSnapshot(ec2Svc, securityGroup)

		// arn:aws:ec2:region:account-id:security-group/sg-id
		resourceID := strings.Join(
			[]string{
				"arn",
				pollerInput.AuthSourceParsedARN.Partition,
				"ec2",
				*pollerInput.Region,
				*ec2SecurityGroupSnapshot.OwnerId,
				"security-group/" + *ec2SecurityGroupSnapshot.ID,
			},
			":",
		)

		// Populate generic fields
		ec2SecurityGroupSnapshot.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		ec2SecurityGroupSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		ec2SecurityGroupSnapshot.Region = pollerInput.Region
		ec2SecurityGroupSnapshot.ARN = aws.String(resourceID)

		if _, ok := ec2SecurityGroupSnapshots[resourceID]; !ok {
			ec2SecurityGroupSnapshots[resourceID] = ec2SecurityGroupSnapshot
		} else {
			zap.L().Info("overwriting existing EC2 Security Group snapshot",
				zap.String("resourceId", resourceID))
			ec2SecurityGroupSnapshots[resourceID] = ec2SecurityGroupSnapshot
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(ec2SecurityGroupSnapshots))
	for resourceID, ec2SecurityGroupSnapshot := range ec2SecurityGroupSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      ec2SecurityGroupSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.Ec2SecurityGroupSchema,
		})
	}

	return resources, marker, nil
}
