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
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
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

	policy, err := getIAMPolicy(iamClient, scanRequest.ResourceID)
	if err != nil || policy == nil {
		return nil, err
	}

	snapshot, err := buildIAMPolicySnapshot(iamClient, policy)
	if err != nil {
		return nil, err
	}

	snapshot.AccountID = aws.String(resourceARN.AccountID)
	return snapshot, nil
}

// getPolicy returns a specific IAM policy
func getIAMPolicy(svc iamiface.IAMAPI, policyARN *string) (*iam.Policy, error) {
	policy, err := svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: policyARN,
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == iam.ErrCodeNoSuchEntityException {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *policyARN),
				zap.String("resourceType", awsmodels.IAMPolicySchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "IAM.GetPolicy: %s", aws.StringValue(policyARN))
	}
	return policy.Policy, nil
}

// listPolicies returns all IAM policies in the account
func listPolicies(iamSvc iamiface.IAMAPI, nextMarker *string) (policies []*iam.Policy, marker *string, err error) {
	err = iamSvc.ListPoliciesPages(
		&iam.ListPoliciesInput{
			// We only want to scan Customer managed policies
			Scope:    aws.String(localPolicyScope),
			MaxItems: aws.Int64(int64(defaultBatchSize)),
			Marker:   nextMarker,
		},
		func(page *iam.ListPoliciesOutput, lastPage bool) bool {
			return iamPolicyIterator(page, &policies, &marker)
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "IAM.ListPoliciesPages")
	}

	return
}

func iamPolicyIterator(page *iam.ListPoliciesOutput, policies *[]*iam.Policy, marker **string) bool {
	*policies = append(*policies, page.Policies...)
	*marker = page.Marker
	return len(*policies) < defaultBatchSize
}

// listEntitiesForPolicy returns the entities that have the given policy
func listEntitiesForPolicy(
	iamSvc iamiface.IAMAPI, arn *string) (*awsmodels.IAMPolicyEntities, error) {

	entities := &awsmodels.IAMPolicyEntities{}
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
		return nil, errors.Wrapf(err, "IAM.ListEntitiesForPolicyPages: %s", aws.StringValue(arn))
	}
	return entities, nil
}

// getPolicyVersion returns a specific policy document given a policy ARN and version number
func getPolicyVersion(
	iamSvc iamiface.IAMAPI, arn *string, version *string) (string, error) {

	policy, err := iamSvc.GetPolicyVersion(
		&iam.GetPolicyVersionInput{PolicyArn: arn, VersionId: version},
	)
	if err != nil {
		return "", errors.Wrapf(err, "IAM.GetPolicyVersion: policy %s, version %s", aws.StringValue(arn), aws.StringValue(version))
	}

	policyDoc, err := url.QueryUnescape(*policy.PolicyVersion.Document)
	if err != nil {
		return "", errors.Wrapf(err, "failed to url decode policy document for policy %s", aws.StringValue(arn))
	}

	return policyDoc, nil
}

// buildIAMPolicySnapshot builds a complete IAMPolicySnapshot
func buildIAMPolicySnapshot(iamSvc iamiface.IAMAPI, policy *iam.Policy) (*awsmodels.IAMPolicy, error) {
	policySnapshot := &awsmodels.IAMPolicy{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   policy.Arn,
			TimeCreated:  policy.CreateDate,
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

	var err error
	policySnapshot.Entities, err = listEntitiesForPolicy(iamSvc, policy.Arn)
	if err != nil {
		return nil, err
	}

	policyDocument, err := getPolicyVersion(iamSvc, policy.Arn, policy.DefaultVersionId)
	if err != nil {
		return nil, err
	}
	policySnapshot.PolicyDocument = aws.String(policyDocument)

	return policySnapshot, nil
}

// PollIamPolicies gathers information on each IAM policy for an AWS account.
func PollIamPolicies(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting IAM Policy resource poller")
	iamSvc, err := getIAMClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all policies
	policies, marker, err := listPolicies(iamSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, err
	}

	var resources []apimodels.AddResourceEntry
	for _, policy := range policies {
		iamPolicySnapshot, err := buildIAMPolicySnapshot(iamSvc, policy)
		if err != nil {
			return nil, nil, err
		}
		iamPolicySnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      iamPolicySnapshot,
			ID:              *iamPolicySnapshot.ARN,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.IAMPolicySchema,
		})
	}

	return resources, marker, nil
}
