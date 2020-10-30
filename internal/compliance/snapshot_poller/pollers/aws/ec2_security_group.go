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
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
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
	securityGroup, err := getSecurityGroup(ec2Client, aws.String(sgID))
	if err != nil {
		return nil, err
	}

	snapshot := buildEc2SecurityGroupSnapshot(securityGroup)
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
func getSecurityGroup(svc ec2iface.EC2API, securityGroupID *string) (*ec2.SecurityGroup, error) {
	securityGroup, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{securityGroupID},
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "InvalidGroup.NotFound" {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *securityGroupID),
				zap.String("resourceType", awsmodels.Ec2SecurityGroupSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "EC2.DescribeSecurityGroups: %s", aws.StringValue(securityGroupID))
	}

	if len(securityGroup.SecurityGroups) != 1 {
		return nil, errors.WithMessagef(
			errors.New("EC2.DescribeSecurityGroups"),
			"expected exactly one security group when describing %s, but found %d security groups",
			aws.StringValue(securityGroupID),
			len(securityGroup.SecurityGroups),
		)
	}
	return securityGroup.SecurityGroups[0], nil
}

// describeSecurityGroupsPages returns all Security Groups for a given region
func describeSecurityGroups(ec2Svc ec2iface.EC2API, nextMarker *string) (securityGroups []*ec2.SecurityGroup, marker *string, err error) {
	err = ec2Svc.DescribeSecurityGroupsPages(&ec2.DescribeSecurityGroupsInput{
		NextToken:  nextMarker,
		MaxResults: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *ec2.DescribeSecurityGroupsOutput, lastPage bool) bool {
			return ec2SecurityGroupIterator(page, &securityGroups, &marker)
		})

	if err != nil {
		return nil, nil, errors.Wrap(err, "EC2.DescribeSecurityGroupsPages")
	}
	return
}

func ec2SecurityGroupIterator(page *ec2.DescribeSecurityGroupsOutput, groups *[]*ec2.SecurityGroup, marker **string) bool {
	*groups = append(*groups, page.SecurityGroups...)
	*marker = page.NextToken
	return len(*groups) < defaultBatchSize
}

func buildEc2SecurityGroupSnapshot(securityGroup *ec2.SecurityGroup) *awsmodels.Ec2SecurityGroup {
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
func PollEc2SecurityGroups(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 Security Group resource poller")

	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all Security Groups
	securityGroups, marker, err := describeSecurityGroups(ec2Svc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// For each Security Group, build out a full snapshot
	resources := make([]apimodels.AddResourceEntry, 0, len(securityGroups))
	for _, securityGroup := range securityGroups {
		ec2SecurityGroupSnapshot := buildEc2SecurityGroupSnapshot(securityGroup)

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

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      ec2SecurityGroupSnapshot,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.Ec2SecurityGroupSchema,
		})
	}

	return resources, marker, nil
}
