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
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
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
	group := getGroup(iamClient, aws.String(resourceSplit[len(resourceSplit)-1]))
	if group == nil {
		return nil, nil
	}

	snapshot := buildIamGroupSnapshot(iamClient, group.Group)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	scanRequest.ResourceID = snapshot.ResourceID
	return snapshot, nil
}

// listGroups returns a list of all IAM groups in the account
func listGroups(iamSvc iamiface.IAMAPI) (groups []*iam.Group) {
	err := iamSvc.ListGroupsPages(&iam.ListGroupsInput{},
		func(page *iam.ListGroupsOutput, lastPage bool) bool {
			groups = append(groups, page.Groups...)
			return true
		})
	if err != nil {
		utils.LogAWSError("IAM.ListGroups", err)
	}
	return
}

// getGroup provides detailed information about a given IAM Group
func getGroup(iamSvc iamiface.IAMAPI, name *string) *iam.GetGroupOutput {
	out, err := iamSvc.GetGroup(&iam.GetGroupInput{GroupName: name})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "NoSuchEntity" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *name),
					zap.String("resourceType", awsmodels.IAMGroupSchema))
				return nil
			}
		}
		utils.LogAWSError("IAM.GetGroup", err)
		return nil
	}

	return out
}

// listGroupPolicies returns all the inline IAM policies for a given IAM group
func listGroupPolicies(iamSvc iamiface.IAMAPI, groupName *string) (policies []*string) {
	err := iamSvc.ListGroupPoliciesPages(&iam.ListGroupPoliciesInput{GroupName: groupName},
		func(page *iam.ListGroupPoliciesOutput, lastPage bool) bool {
			policies = append(policies, page.PolicyNames...)
			return true
		})
	if err != nil {
		utils.LogAWSError("IAM.ListGroupPoliciesPages", err)
		return nil
	}
	return
}

// listAttachedGroupPolicies returns all the managed IAM policies for a given IAM group
func listAttachedGroupPolicies(iamSvc iamiface.IAMAPI, groupName *string) (policies []*string) {
	err := iamSvc.ListAttachedGroupPoliciesPages(&iam.ListAttachedGroupPoliciesInput{GroupName: groupName},
		func(page *iam.ListAttachedGroupPoliciesOutput, lastPage bool) bool {
			for _, policy := range page.AttachedPolicies {
				policies = append(policies, policy.PolicyArn)
			}
			return true
		})
	if err != nil {
		utils.LogAWSError("IAM.ListGroups", err)
		return nil
	}
	return
}

// getGroupPolicy returns the policy document for a given IAM group and inline policy name
func getGroupPolicy(iamSvc iamiface.IAMAPI, groupName *string, policyName *string) *string {
	out, err := iamSvc.GetGroupPolicy(
		&iam.GetGroupPolicyInput{GroupName: groupName, PolicyName: policyName},
	)

	if err != nil {
		utils.LogAWSError("IAM.GetGroupPolicy", err)
		return nil
	}

	decodedPolicy, err := url.QueryUnescape(*out.PolicyDocument)
	if err != nil {
		zap.L().Error("IAM: unable to url decode inline policy document",
			zap.String("policy document", *out.PolicyDocument),
			zap.String("policy name", *policyName),
			zap.String("group", *groupName),
		)
		return nil
	}
	return aws.String(decodedPolicy)
}

// buildIamGroupSnapshot makes all the calls to build up a snapshot of a given IAM Group
func buildIamGroupSnapshot(iamSvc iamiface.IAMAPI, group *iam.Group) *awsmodels.IamGroup {
	if group == nil {
		return nil
	}
	iamGroupSnapshot := &awsmodels.IamGroup{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   group.Arn,
			TimeCreated:  utils.DateTimeFormat(*group.CreateDate),
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

	fullGroup := getGroup(iamSvc, group.GroupName)
	if fullGroup == nil {
		return nil
	}

	iamGroupSnapshot.Users = fullGroup.Users
	iamGroupSnapshot.ManagedPolicyARNs = listAttachedGroupPolicies(iamSvc, group.GroupName)

	inlinePolicyNames := listGroupPolicies(iamSvc, group.GroupName)
	if inlinePolicyNames != nil {
		iamGroupSnapshot.InlinePolicies = make(map[string]*string, len(inlinePolicyNames))
		for _, inlinePolicyName := range inlinePolicyNames {
			iamGroupSnapshot.InlinePolicies[*inlinePolicyName] = getGroupPolicy(
				iamSvc,
				group.GroupName,
				inlinePolicyName,
			)
		}
	}

	return iamGroupSnapshot
}

// PollIamGroups gathers information on each IAM Group for an AWS account.
func PollIamGroups(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting IAM Group resource poller")
	iamSvc, err := getIAMClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	// Start with generating a list of all keys
	groups := listGroups(iamSvc)
	if len(groups) == 0 {
		zap.L().Debug("No IAM groups found.")
		return nil, nil
	}

	var resources []*apimodels.AddResourceEntry
	for _, group := range groups {
		iamGroupSnapshot := buildIamGroupSnapshot(iamSvc, group)
		if iamGroupSnapshot == nil {
			continue
		}
		iamGroupSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      iamGroupSnapshot,
			ID:              apimodels.ResourceID(*iamGroupSnapshot.ARN),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.IAMGroupSchema,
		})
	}

	return resources, nil
}
