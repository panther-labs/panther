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
	nacl, err := getNetworkACL(ec2Client, aws.String(naclID))
	if err != nil {
		return nil, err
	}

	snapshot := buildEc2NetworkAclSnapshot(nacl)
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
func getNetworkACL(svc ec2iface.EC2API, networkACLID *string) (*ec2.NetworkAcl, error) {
	nacl, err := svc.DescribeNetworkAcls(&ec2.DescribeNetworkAclsInput{
		NetworkAclIds: []*string{networkACLID},
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == "InvalidNetworkAclID.NotFound" {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *networkACLID),
				zap.String("resourceType", awsmodels.Ec2NetworkAclSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "EC2.DescribeNetworkACLs: %s", aws.StringValue(networkACLID))
	}

	if len(nacl.NetworkAcls) != 1 {
		return nil, errors.WithMessagef(
			errors.New("EC2.DescribeNetworkACLs"),
			"expected exactly one network ACL when describing %s, but found %d network ACLs",
			aws.StringValue(networkACLID),
			len(nacl.NetworkAcls),
		)
	}
	return nacl.NetworkAcls[0], nil
}

// describeNetworkAclsPages returns all Network ACLs for a given region
func describeNetworkAcls(ec2Svc ec2iface.EC2API, nextMarker *string) (networkACLs []*ec2.NetworkAcl, marker *string, err error) {
	err = ec2Svc.DescribeNetworkAclsPages(&ec2.DescribeNetworkAclsInput{
		NextToken:  nextMarker,
		MaxResults: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *ec2.DescribeNetworkAclsOutput, lastPage bool) bool {
			return ec2NaclIterator(page, &networkACLs, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "EC2.DescribeNetworkAclsPages")
	}
	return
}

func ec2NaclIterator(page *ec2.DescribeNetworkAclsOutput, networkACLs *[]*ec2.NetworkAcl, marker **string) bool {
	*networkACLs = append(*networkACLs, page.NetworkAcls...)
	*marker = page.NextToken
	return len(*networkACLs) < defaultBatchSize
}

func buildEc2NetworkAclSnapshot(networkACL *ec2.NetworkAcl) *awsmodels.Ec2NetworkAcl {
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
func PollEc2NetworkAcls(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting EC2 Network ACL resource poller")
	ec2Svc, err := getEC2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all Network ACLs
	networkACLs, marker, err := describeNetworkAcls(ec2Svc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// For each Network ACL, build out a full snapshot
	resources := make([]apimodels.AddResourceEntry, 0, len(networkACLs))
	for _, networkACL := range networkACLs {
		ec2NetworkACLSnapshot := buildEc2NetworkAclSnapshot(networkACL)

		// arn:aws:ec2:region:account-id:network-acl/nacl-id
		resourceID := strings.Join(
			[]string{
				"arn",
				pollerInput.AuthSourceParsedARN.Partition,
				"ec2",
				*pollerInput.Region,
				*ec2NetworkACLSnapshot.OwnerId,
				"network-acl/" + *ec2NetworkACLSnapshot.ID,
			},
			":",
		)

		// Populate generic fields
		ec2NetworkACLSnapshot.ResourceID = aws.String(resourceID)

		// Populate AWS generic fields
		ec2NetworkACLSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		ec2NetworkACLSnapshot.Region = pollerInput.Region
		ec2NetworkACLSnapshot.ARN = aws.String(resourceID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      ec2NetworkACLSnapshot,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.Ec2NetworkAclSchema,
		})
	}

	return resources, marker, nil
}
