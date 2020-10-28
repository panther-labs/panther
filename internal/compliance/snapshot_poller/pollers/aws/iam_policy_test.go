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
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestIAMPolicyList(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListPoliciesPages"})

	out, marker, err := listPolicies(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestIamPolicyListIterator(t *testing.T) {
	var policies []*iam.Policy
	var marker *string

	cont := iamPolicyIterator(awstest.ExampleListPolicies, &policies, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, policies, 1)

	for i := 1; i < 50; i++ {
		cont = iamPolicyIterator(awstest.ExampleListPoliciesContinue, &policies, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, policies, 1+i*2)
	}

	cont = iamPolicyIterator(awstest.ExampleListPoliciesContinue, &policies, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, policies, 101)
}

func TestIAMPolicyListError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListPoliciesPages"})

	out, marker, err := listPolicies(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestIAMPolicyVersion(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetPolicyVersion"})

	out, err := getPolicyVersion(
		mockSvc,
		aws.String("arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"),
		aws.String("v2"),
	)

	assert.NoError(t, err)
	assert.Equal(t, *awstest.ExamplePolicyDocumentDecoded, out)
	mockSvc.AssertExpectations(t)
}

func TestIAMPolicyVersionError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GetPolicyVersion"})

	out, err := getPolicyVersion(
		mockSvc,
		aws.String("arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"),
		aws.String("v2"),
	)

	require.NotNil(t, err)
	assert.Empty(t, out)
	mockSvc.AssertExpectations(t)
}

func TestIAMPolicyListEntities(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListEntitiesForPolicyPages"})

	out, err := listEntitiesForPolicy(
		mockSvc,
		aws.String("arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"),
	)

	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestIAMPolicyListEntitiesError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListEntitiesForPolicyPages"})

	out, err := listEntitiesForPolicy(
		mockSvc,
		aws.String("arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"),
	)

	assert.Empty(t, out)
	assert.Error(t, err)
}

func TestIAMPolicyBuildSnapshot(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcAll()

	out, err := buildIAMPolicySnapshot(mockSvc, awstest.ExampleListPolicies.Policies[0])
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestIAMPolicyBuildSnapshotError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcAllError()

	out, err := buildIAMPolicySnapshot(mockSvc, awstest.ExampleListPolicies.Policies[0])
	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestIAMPolicyPoller(t *testing.T) {
	resetCache()
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAll()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIamPolicies(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NoError(t, err)
	assert.Len(t, resources, 1)
	assert.Equal(t, *awstest.ExampleListPolicies.Policies[0].Arn, resources[0].ID)
	assert.Nil(t, marker)
}

func TestIAMPolicyPollerError(t *testing.T) {
	resetCache()
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAllError()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIamPolicies(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Nil(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}
