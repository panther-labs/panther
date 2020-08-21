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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestIAMRolesList(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListRolesPages"})

	out, marker, err := listRoles(mockSvc, nil)
	assert.Equal(t, awstest.ExampleIAMRole, out[0])
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestIAMRolesListError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListRolesPages"})

	out, marker, err := listRoles(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestIAMRolesGetPolicy(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetRolePolicy"})

	out, err := getRolePolicy(mockSvc, aws.String("RoleName"), aws.String("PolicyName"))
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestIAMRolesGetPolicyError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListRolesPages"})

	out, marker, err := listRoles(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestIAMRolesGetPolicies(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{
		"ListRolePoliciesPages",
		"ListAttachedRolePoliciesPages",
	})

	inlinePolicies, managedPolicies, err := getRolePolicies(mockSvc, aws.String("Franklin"))
	require.NoError(t, err)
	assert.Equal(
		t,
		[]*string{aws.String("AdministratorAccess")},
		managedPolicies,
	)
	assert.Equal(
		t,
		[]*string{aws.String("KinesisWriteOnly"), aws.String("SQSCreateQueue")},
		inlinePolicies,
	)
}

func TestIAMRolesGetPoliciesErrors(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{
		"ListRolePoliciesPages",
		"ListAttachedRolePoliciesPages",
	})

	inlinePolicies, managedPolicies, err := getRolePolicies(mockSvc, aws.String("Franklin"))
	require.Error(t, err)
	assert.Empty(t, inlinePolicies)
	assert.Empty(t, managedPolicies)
}

func TestIAMRolesPoller(t *testing.T) {
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAll()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIAMRoles(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NotEmpty(t, resources)
	assert.Len(t, resources, 1)
	assert.Equal(t, awstest.ExampleIAMRole.Arn, resources[0].Attributes.(*awsmodels.IAMRole).ARN)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestIAMRolesPollerError(t *testing.T) {
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAllError()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIAMRoles(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Nil(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}
