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

// PollIAMRole polls a single IAM Role resource
func PollIAMRole(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	iamClient, err := getIAMClient(pollerResourceInput, defaultRegion)
	if err != nil {
		return nil, err
	}

	// The event processor sometimes includes resource paths for IAM resources, and sometimes does
	// not (depending on whether that information is available in CloudTrail). This extracts just
	// the actual resource name from the ARN.
	resourceSplit := strings.Split(resourceARN.Resource, "/")
	role := getRole(iamClient, aws.String(resourceSplit[len(resourceSplit)-1]))

	snapshot := BuildIAMRoleSnapshot(iamClient, role)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	// Set the correct ResourceID in case the event processor sent it without the path.
	scanRequest.ResourceID = snapshot.ResourceID
	return snapshot, nil
}

// getRole returns a specific IAM role
func getRole(svc iamiface.IAMAPI, roleName *string) *iam.Role {
	role, err := svc.GetRole(&iam.GetRoleInput{
		RoleName: roleName,
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "NoSuchEntity" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *roleName),
					zap.String("resourceType", awsmodels.IAMRoleSchema))
				return nil
			}
		}
		utils.LogAWSError("IAM.GetRole", err)
		return nil
	}
	return role.Role
}

// listUsers returns an array of all users in the account, excluding the root account.
func listRoles(iamSvc iamiface.IAMAPI) (roles []*iam.Role) {
	err := iamSvc.ListRolesPages(
		&iam.ListRolesInput{},
		func(page *iam.ListRolesOutput, lastPage bool) bool {
			roles = append(roles, page.Roles...)
			return true
		},
	)
	if err != nil {
		utils.LogAWSError("IAM.ListRolesPages", err)
	}
	return
}

// getRolePolicy returns the policy document for a given IAM Role and inline policy name
func getRolePolicy(iamSvc iamiface.IAMAPI, roleName *string, policyName *string) *string {
	policy, err := iamSvc.GetRolePolicy(&iam.GetRolePolicyInput{RoleName: roleName, PolicyName: policyName})
	if err != nil {
		utils.LogAWSError("IAM.GetRolePolicy", err)
		return nil
	}

	decodedPolicy, err := url.QueryUnescape(*policy.PolicyDocument)
	if err != nil {
		zap.L().Error("IAM: unable to url decode inline policy document",
			zap.String("policy document", *policy.PolicyDocument),
			zap.String("policy name", *policyName),
			zap.String("role", *roleName),
		)
		return nil
	}
	return aws.String(decodedPolicy)
}

// getRolePolicies aggregates all the policies assigned to a user by polling both
// the ListRolePolicies and ListAttachedRolePolicies APIs.
func getRolePolicies(iamSvc iamiface.IAMAPI, roleName *string) (
	inlinePolicies []*string, managedPolicies []*string, err error) {

	err = iamSvc.ListRolePoliciesPages(
		&iam.ListRolePoliciesInput{RoleName: roleName},
		func(page *iam.ListRolePoliciesOutput, lastPage bool) bool {
			inlinePolicies = append(inlinePolicies, page.PolicyNames...)
			return true
		},
	)
	if err != nil {
		utils.LogAWSError("IAM.ListRolePolicies", err)
	}

	err = iamSvc.ListAttachedRolePoliciesPages(
		&iam.ListAttachedRolePoliciesInput{RoleName: roleName},
		func(page *iam.ListAttachedRolePoliciesOutput, lastPage bool) bool {
			for _, attachedPolicy := range page.AttachedPolicies {
				managedPolicies = append(managedPolicies, attachedPolicy.PolicyName)
			}
			return true
		},
	)
	if err != nil {
		utils.LogAWSError("IAM.ListAttachedRolePolicies", err)
	}

	return
}

// buildIAMRoleSnapshot builds an IAMRoleSnapshot for a given IAM Role
func BuildIAMRoleSnapshot(iamSvc iamiface.IAMAPI, role *iam.Role) *awsmodels.IAMRole {
	if role == nil {
		return nil
	}
	iamRoleSnapshot := &awsmodels.IAMRole{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   role.Arn,
			TimeCreated:  utils.DateTimeFormat(*role.CreateDate),
			ResourceType: aws.String(awsmodels.IAMRoleSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:    role.Arn,
			Name:   role.RoleName,
			ID:     role.RoleId,
			Region: aws.String(awsmodels.GlobalRegion),
			Tags:   utils.ParseTagSlice(role.Tags),
		},
		AssumeRolePolicyDocument: role.AssumeRolePolicyDocument,
		Description:              role.Description,
		MaxSessionDuration:       role.MaxSessionDuration,
		Path:                     role.Path,
		PermissionsBoundary:      role.PermissionsBoundary,
	}

	// Decode the assume policy document, and overwrite the existing URL encoded one
	assumeRolePolicyDocument, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
	if err != nil {
		zap.L().Error(
			"unable to parse IAM Role AssumeRolePolicyDocument",
			zap.String("roleID", *role.RoleId),
		)
	} else {
		iamRoleSnapshot.AssumeRolePolicyDocument = aws.String(assumeRolePolicyDocument)
	}

	// Get IAM Policies associated to the Role.
	// There is no error logging here because it is logged in getRolePolicies.
	inlinePolicies, managedPolicies, err := getRolePolicies(iamSvc, role.RoleName)
	if err == nil {
		iamRoleSnapshot.ManagedPolicyNames = managedPolicies
		if inlinePolicies != nil {
			iamRoleSnapshot.InlinePolicies = make(map[string]*string, len(inlinePolicies))
			for _, inlinePolicy := range inlinePolicies {
				iamRoleSnapshot.InlinePolicies[*inlinePolicy] = getRolePolicy(iamSvc, role.RoleName, inlinePolicy)
			}
		}
	}

	return iamRoleSnapshot
}

// PollIAMRoles generates a snapshot for each IAM Role.
func PollIAMRoles(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting IAM Role resource poller")
	iamSvc, err := getIAMClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	// List all IAM Roles in the account
	roles := listRoles(iamSvc)
	if len(roles) == 0 {
		zap.L().Debug("no IAM roles found")
		return nil, nil
	}

	// Create IAM Role snapshots
	var resources []*apimodels.AddResourceEntry
	for _, role := range roles {
		// The IAM.Role struct has a Tags field, indicating what tags the Role has
		// The API call IAM.GetRole returns an IAM.Role struct, with all appropriate fields set
		// The API call IAM.ListRoles returns a slice of IAM.Role structs, but does not set the tags
		// field for any of these structs regardless of whether the corresponding role has tags set
		// This patches that gap
		fullRole := getRole(iamSvc, role.RoleName)
		iamRoleSnapshot := BuildIAMRoleSnapshot(iamSvc, fullRole)
		if iamRoleSnapshot == nil {
			continue
		}
		iamRoleSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      iamRoleSnapshot,
			ID:              apimodels.ResourceID(*role.Arn),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.IAMRoleSchema,
		})
	}

	return resources, nil
}
