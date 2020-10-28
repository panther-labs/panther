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
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
)

// PollIAMGroup polls a single IAM Group resource
func PollIAMGroup(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	iamClient, err := getIAMClient(pollerResourceInput, defaultRegion)
	if err != nil {
		return nil, err
	}

	// See PollIAMRole for an explanation of this behavior
	resourceSplit := strings.Split(resourceARN.Resource, "/")
	group, err := getGroup(iamClient, aws.String(resourceSplit[len(resourceSplit)-1]))
	if err != nil || group == nil {
		return nil, err
	}

	snapshot, err := buildIamGroupSnapshot(iamClient, group.Group)
	if err != nil {
		return nil, err
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	scanRequest.ResourceID = snapshot.ResourceID
	return snapshot, nil
}

// listGroups returns a list of all IAM groups in the account
func listGroups(iamSvc iamiface.IAMAPI, nextMarker *string) (groups []*iam.Group, marker *string, err error) {
	err = iamSvc.ListGroupsPages(&iam.ListGroupsInput{
		Marker:   nextMarker,
		MaxItems: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *iam.ListGroupsOutput, lastPage bool) bool {
			return iamGroupIterator(page, &groups, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "IAM.ListGroupsPages")
	}
	return
}

func iamGroupIterator(page *iam.ListGroupsOutput, groups *[]*iam.Group, marker **string) bool {
	*groups = append(*groups, page.Groups...)
	*marker = page.Marker
	return len(*groups) < defaultBatchSize
}

// getGroup provides detailed information about a given IAM Group
func getGroup(iamSvc iamiface.IAMAPI, name *string) (*iam.GetGroupOutput, error) {
	out, err := iamSvc.GetGroup(&iam.GetGroupInput{GroupName: name})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == iam.ErrCodeNoSuchEntityException {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *name),
				zap.String("resourceType", awsmodels.IAMGroupSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "IAM.GetGroup: %s", aws.StringValue(name))
	}

	return out, nil
}

// listGroupPolicies returns all the inline IAM policies for a given IAM group
func listGroupPolicies(iamSvc iamiface.IAMAPI, groupName *string) (policies []*string, err error) {
	err = iamSvc.ListGroupPoliciesPages(&iam.ListGroupPoliciesInput{GroupName: groupName},
		func(page *iam.ListGroupPoliciesOutput, lastPage bool) bool {
			policies = append(policies, page.PolicyNames...)
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "IAM.ListGroupPoliciesPages: %s", aws.StringValue(groupName))
	}
	return
}

// listAttachedGroupPolicies returns all the managed IAM policies for a given IAM group
func listAttachedGroupPolicies(iamSvc iamiface.IAMAPI, groupName *string) (policies []*string, err error) {
	err = iamSvc.ListAttachedGroupPoliciesPages(&iam.ListAttachedGroupPoliciesInput{GroupName: groupName},
		func(page *iam.ListAttachedGroupPoliciesOutput, lastPage bool) bool {
			for _, policy := range page.AttachedPolicies {
				policies = append(policies, policy.PolicyArn)
			}
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "IAM.ListGroups: %s", aws.StringValue(groupName))
	}
	return
}

// getGroupPolicy returns the policy document for a given IAM group and inline policy name
func getGroupPolicy(iamSvc iamiface.IAMAPI, groupName *string, policyName *string) (*string, error) {
	out, err := iamSvc.GetGroupPolicy(&iam.GetGroupPolicyInput{GroupName: groupName, PolicyName: policyName})

	if err != nil {
		return nil, errors.Wrapf(err, "IAM.GetGroupPolicy: %s", aws.StringValue(groupName))
	}

	decodedPolicy, err := url.QueryUnescape(*out.PolicyDocument)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"unable to url decode inline policy document %s for group %s",
			aws.StringValue(policyName),
			aws.StringValue(groupName),
		)
	}
	return aws.String(decodedPolicy), nil
}

// buildIamGroupSnapshot makes all the calls to build up a snapshot of a given IAM Group
func buildIamGroupSnapshot(iamSvc iamiface.IAMAPI, group *iam.Group) (*awsmodels.IamGroup, error) {
	iamGroupSnapshot := &awsmodels.IamGroup{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   group.Arn,
			TimeCreated:  group.CreateDate,
			ResourceType: aws.String(awsmodels.IAMGroupSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:    group.Arn,
			ID:     group.GroupId,
			Name:   group.GroupName,
			Region: aws.String(awsmodels.GlobalRegion),
		},
		Path: group.Path,
	}

	fullGroup, err := getGroup(iamSvc, group.GroupName)
	// fullGroup could be nil if the resource has been deleted between scan start time and now
	if err != nil || fullGroup == nil {
		return nil, err
	}

	iamGroupSnapshot.Users = fullGroup.Users
	iamGroupSnapshot.ManagedPolicyARNs, err = listAttachedGroupPolicies(iamSvc, group.GroupName)
	if err != nil {
		return nil, err
	}

	inlinePolicyNames, err := listGroupPolicies(iamSvc, group.GroupName)
	if err != nil {
		return nil, err
	}
	iamGroupSnapshot.InlinePolicies = make(map[string]*string, len(inlinePolicyNames))
	for _, inlinePolicyName := range inlinePolicyNames {
		iamGroupSnapshot.InlinePolicies[*inlinePolicyName], err = getGroupPolicy(
			iamSvc,
			group.GroupName,
			inlinePolicyName,
		)
		if err != nil {
			return nil, err
		}
	}

	return iamGroupSnapshot, nil
}

// PollIamGroups gathers information on each IAM Group for an AWS account.
func PollIamGroups(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting IAM Group resource poller")
	iamSvc, err := getIAMClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all groups
	groups, marker, err := listGroups(iamSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, err
	}

	var resources []apimodels.AddResourceEntry
	for _, group := range groups {
		iamGroupSnapshot, err := buildIamGroupSnapshot(iamSvc, group)
		if err != nil {
			return nil, nil, err
		}
		iamGroupSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      iamGroupSnapshot,
			ID:              *iamGroupSnapshot.ARN,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.IAMGroupSchema,
		})
	}

	return resources, marker, nil
}
