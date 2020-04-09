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

const (
	localPolicyScope = "Local"
)

// PollIAMPolicy polls a single IAM Policy resource
func PollIAMPolicy(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	iamClient, err := getIAMClient(pollerResourceInput, defaultRegion)
	if err != nil {
		return nil, err
	}

	policy := getIAMPolicy(iamClient, scanRequest.ResourceID)

	snapshot := buildIAMPolicySnapshot(iamClient, policy)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	return snapshot, nil
}

// getPolicy returns a specific IAM policy
func getIAMPolicy(svc iamiface.IAMAPI, policyARN *string) *iam.Policy {
	policy, err := svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: policyARN,
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "NoSuchEntity" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *policyARN),
					zap.String("resourceType", awsmodels.IAMPolicySchema))
				return nil
			}
		}
		utils.LogAWSError("IAM.GetPolicy", err)
		return nil
	}
	return policy.Policy
}

// listPolicies returns all IAM policies in the account
func listPolicies(iamSvc iamiface.IAMAPI) (policies []*iam.Policy, err error) {
	err = iamSvc.ListPoliciesPages(
		// We only want to scan Customer managed policies
		&iam.ListPoliciesInput{Scope: aws.String(localPolicyScope)},
		func(page *iam.ListPoliciesOutput, lastPage bool) bool {
			policies = append(policies, page.Policies...)
			return true
		},
	)

	return
}

// listEntitiesForPolicy returns the entities that have the given policy
func listEntitiesForPolicy(
	iamSvc iamiface.IAMAPI, arn *string) (entities *awsmodels.IAMPolicyEntities) {

	entities = &awsmodels.IAMPolicyEntities{}
	err := iamSvc.ListEntitiesForPolicyPages(
		&iam.ListEntitiesForPolicyInput{PolicyArn: arn},
		func(page *iam.ListEntitiesForPolicyOutput, lastPage bool) bool {
			entities.PolicyGroups = append(entities.PolicyGroups, page.PolicyGroups...)
			entities.PolicyRoles = append(entities.PolicyRoles, page.PolicyRoles...)
			entities.PolicyUsers = append(entities.PolicyUsers, page.PolicyUsers...)
			return true
		},
	)
	if err != nil {
		utils.LogAWSError("IAM.ListEntitiesForPolicyPages", err)
	}
	return
}

// getPolicyVersion returns a specific policy document given a policy ARN and version number
func getPolicyVersion(
	iamSvc iamiface.IAMAPI, arn *string, version *string) (policyDoc string, err error) {

	policy, err := iamSvc.GetPolicyVersion(
		&iam.GetPolicyVersionInput{PolicyArn: arn, VersionId: version},
	)
	if err != nil {
		return
	}

	policyDoc, err = url.QueryUnescape(*policy.PolicyVersion.Document)
	return
}

// buildIAMPolicySnapshot builds a complete IAMPolicySnapshot
func buildIAMPolicySnapshot(iamSvc iamiface.IAMAPI, policy *iam.Policy) *awsmodels.IAMPolicy {
	if policy == nil {
		return nil
	}

	policySnapshot := &awsmodels.IAMPolicy{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   policy.Arn,
			TimeCreated:  utils.DateTimeFormat(*policy.CreateDate),
			ResourceType: aws.String(awsmodels.IAMPolicySchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:    policy.Arn,
			Name:   policy.PolicyName,
			ID:     policy.PolicyId,
			Region: aws.String(awsmodels.GlobalRegion),
		},
		AttachmentCount:               policy.AttachmentCount,
		DefaultVersionId:              policy.DefaultVersionId,
		Description:                   policy.Description,
		IsAttachable:                  policy.IsAttachable,
		Path:                          policy.Path,
		PermissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount,
		UpdateDate:                    policy.UpdateDate,
	}

	policySnapshot.Entities = listEntitiesForPolicy(iamSvc, policy.Arn)

	policyDocument, err := getPolicyVersion(iamSvc, policy.Arn, policy.DefaultVersionId)
	if err != nil {
		utils.LogAWSError("IAM.GetPolicyVersion", err)
	} else {
		policySnapshot.PolicyDocument = aws.String(policyDocument)
	}

	return policySnapshot
}

// PollIamPolicies gathers information on each IAM policy for an AWS account.
func PollIamPolicies(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting IAM Policy resource poller")
	iamSvc, err := getIAMClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	// Start with generating a list of all policies
	policies, listErr := listPolicies(iamSvc)
	if listErr != nil {
		utils.LogAWSError("IAM.ListPolicies", listErr)
		return nil, nil
	}

	var resources []*apimodels.AddResourceEntry
	for _, policy := range policies {
		iamPolicySnapshot := buildIAMPolicySnapshot(iamSvc, policy)
		if iamPolicySnapshot == nil {
			continue
		}
		iamPolicySnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      iamPolicySnapshot,
			ID:              apimodels.ResourceID(*iamPolicySnapshot.ARN),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.IAMPolicySchema,
		})
	}

	return resources, nil
}
