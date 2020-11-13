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

func TestGetCredentialReport(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetCredentialReport"})

	out, err := getCredentialReport(mockSvc)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestGetCredentialReportError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GetCredentialReport"})

	out, err := getCredentialReport(mockSvc)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestGenerateCredentialReport(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GenerateCredentialReport"})

	out, err := generateCredentialReport(mockSvc)
	require.NoError(t, err)
	assert.Equal(t, awstest.ExampleGenerateCredentialReport, out)
}

func TestGenerateCredentialReportError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GenerateCredentialReport"})

	out, err := generateCredentialReport(mockSvc)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestBuildCredentialReport(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{
		"GenerateCredentialReport",
		"GetCredentialReport",
	})

	credentialReport, err := buildCredentialReport(mockSvc)

	require.NoError(t, err)
	assert.Equal(t, awstest.ExampleExtractedCredentialReport, credentialReport)
}

func TestBuildCredentialReportError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{
		"GenerateCredentialReport",
		"GetCredentialReport",
	})

	credentialReport, err := buildCredentialReport(mockSvc)

	require.NotNil(t, err)
	assert.Empty(t, credentialReport)
}

func TestGenerateCredentialReportInProgress(t *testing.T) {
	awstest.GenerateCredentialReportInProgress = true
	defer func() { awstest.GenerateCredentialReportInProgress = false }()
	mockSvc := awstest.BuildMockIAMSvc([]string{"GenerateCredentialReport"})

	out, err := generateCredentialReport(mockSvc)
	require.NoError(t, err)
	assert.Equal(t, awstest.ExampleGenerateCredentialReport, out)
}

func TestExtractCredentialReport(t *testing.T) {
	out, err := extractCredentialReport(awstest.ExampleCredentialReport.Content)
	require.NoError(t, err)
	assert.Equal(t, awstest.ExampleExtractedCredentialReport, out)
}

func TestExtractCredentialReportError(t *testing.T) {
	badReport := []byte("h1,h2,h3\nv1,v2\nv1,v2,v3,v4,v5\n")
	out, err := extractCredentialReport(badReport)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestIAMUsersList(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListUsersPages"})

	out, marker, err := listUsers(mockSvc, nil)
	assert.Equal(t, awstest.ExampleListUsers.Users, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestIamUserListIterator(t *testing.T) {
	var users []*iam.User
	var marker *string

	cont := iamUserIterator(awstest.ExampleListUsers, &users, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, users, 2)

	for i := 2; i < 50; i++ {
		cont = iamUserIterator(awstest.ExampleListUsersContinue, &users, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, users, i*2)
	}

	cont = iamUserIterator(awstest.ExampleListUsersContinue, &users, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, users, 100)
}

func TestIAMUsersListError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListUsersPages"})

	out, marker, err := listUsers(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestIAMUsersGetPolicy(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"GetUserPolicy"})

	out, err := getUserPolicy(mockSvc, aws.String("ExampleUser"), aws.String("ExamplePolicy"))
	assert.Equal(t, awstest.ExampleGetUserPolicy.PolicyDocument, out)
	assert.NoError(t, err)
}

func TestIAMUsersGetUserPolicyError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"GetUserPolicy"})

	out, err := getUserPolicy(mockSvc, aws.String("ExampleUser"), aws.String("ExamplePolicy"))
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestIAMUsersGetPolicies(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{
		"ListUserPoliciesPages",
		"ListAttachedUserPoliciesPages",
	})

	inlinePolicies, managedPolicies, err := getUserPolicies(mockSvc, aws.String("Franklin"))
	require.NoError(t, err)
	assert.Equal(
		t,
		[]*string{aws.String("ForceMFA"), aws.String("IAMAdministrator")},
		managedPolicies,
	)
	assert.Equal(
		t,
		[]*string{aws.String("KinesisWriteOnly"), aws.String("SQSCreateQueue")},
		inlinePolicies,
	)
}

func TestIAMUsersGetPoliciesErrors(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{
		"ListUserPoliciesPages",
		"ListAttachedUserPoliciesPages",
	})

	inlinePolicies, managedPolicies, err := getUserPolicies(mockSvc, aws.String("Franklin"))
	require.Error(t, err)
	assert.Empty(t, inlinePolicies)
	assert.Empty(t, managedPolicies)
}

func TestIAMUsersListVirtualMFADevices(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvc([]string{"ListVirtualMFADevicesPages"})

	expected := map[string]*awsmodels.VirtualMFADevice{
		"123456789012": {
			EnableDate:   &awstest.ExampleTime,
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/root-account-mfa-device"),
		},
		"AAAAAAAQQQQQO2HVVVVVV": {
			EnableDate:   &awstest.ExampleTime,
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/unit_test_user"),
		},
	}

	out, err := listVirtualMFADevices(mockSvc)
	require.NoError(t, err)
	assert.Equal(t, expected, out)
}

func TestIAMUsersListVirtualMFADevicesError(t *testing.T) {
	mockSvc := awstest.BuildMockIAMSvcError([]string{"ListVirtualMFADevicesPages"})

	out, err := listVirtualMFADevices(mockSvc)
	require.NotNil(t, err)
	assert.Nil(t, out)
}

func TestIAMUsersPoller(t *testing.T) {
	resetCache()
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAll()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIAMUsers(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	rootSnapshot := &awsmodels.IAMRootUser{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   aws.String("arn:aws:iam::123456789012:root"),
			ResourceType: aws.String(awsmodels.IAMRootUserSchema),
			TimeCreated:  &awstest.ExampleTime,
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			AccountID: awstest.ExampleAccountId,
			ARN:       aws.String("arn:aws:iam::123456789012:root"),
			ID:        aws.String("123456789012"),
			Name:      aws.String("<root_account>"),
			Region:    aws.String(awsmodels.GlobalRegion),
		},
		CredentialReport: awstest.ExampleExtractedCredentialReport["<root_account>"],
		VirtualMFA: &awsmodels.VirtualMFADevice{
			EnableDate:   &awstest.ExampleTime,
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/root-account-mfa-device"),
		},
	}

	expectedIamUserSnapshots := []*awsmodels.IAMUser{
		{
			GenericResource: awsmodels.GenericResource{
				ResourceID:   aws.String("arn:aws:iam::123456789012:user/unit_test_user"),
				ResourceType: aws.String(awsmodels.IAMUserSchema),
				TimeCreated:  &awstest.ExampleTime,
			},
			GenericAWSResource: awsmodels.GenericAWSResource{
				AccountID: awstest.ExampleAccountId,
				ARN:       aws.String("arn:aws:iam::123456789012:user/unit_test_user"),
				ID:        aws.String("AAAAAAAQQQQQO2HVVVVVV"),
				Name:      aws.String("unit_test_user"),
				Region:    aws.String(awsmodels.GlobalRegion),
				Tags:      map[string]*string{},
			},
			Path:             aws.String("/service_accounts/"),
			CredentialReport: awstest.ExampleExtractedCredentialReport["unit_test_user"],
			Groups: []*iam.Group{
				awstest.ExampleGroup,
			},
			VirtualMFA: &awsmodels.VirtualMFADevice{
				EnableDate:   &awstest.ExampleTime,
				SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/unit_test_user"),
			},
			InlinePolicies: map[string]*string{
				"KinesisWriteOnly": aws.String("JSON POLICY DOCUMENT"),
				"SQSCreateQueue":   aws.String("JSON POLICY DOCUMENT"),
			},
			ManagedPolicyNames: []*string{aws.String("ForceMFA"), aws.String("IAMAdministrator")},
		},
		{
			GenericResource: awsmodels.GenericResource{
				ResourceID:   aws.String("arn:aws:iam::123456789012:user/Franklin"),
				ResourceType: aws.String(awsmodels.IAMUserSchema),
				TimeCreated:  &awstest.ExampleTime,
			},
			GenericAWSResource: awsmodels.GenericAWSResource{
				AccountID: awstest.ExampleAccountId,
				ARN:       aws.String("arn:aws:iam::123456789012:user/Franklin"),
				ID:        aws.String("AIDA4PIQ2YYOO2HYP2JNV"),
				Name:      aws.String("Franklin"),
				Region:    aws.String(awsmodels.GlobalRegion),
				Tags:      map[string]*string{},
			},
			Path:             aws.String("/"),
			CredentialReport: awstest.ExampleExtractedCredentialReport["Franklin"],
			Groups: []*iam.Group{
				awstest.ExampleGroup,
			},
			VirtualMFA: nil,
			InlinePolicies: map[string]*string{
				"KinesisWriteOnly": aws.String("JSON POLICY DOCUMENT"),
				"SQSCreateQueue":   aws.String("JSON POLICY DOCUMENT"),
			},
			ManagedPolicyNames: []*string{aws.String("ForceMFA"), aws.String("IAMAdministrator")},
		},
	}

	assert.NotEmpty(t, resources)
	// Root and two IAM users
	assert.Len(t, resources, 3)
	assert.Equal(t, expectedIamUserSnapshots[0], resources[0].Attributes)
	assert.Equal(t, expectedIamUserSnapshots[1], resources[1].Attributes)
	assert.Equal(t, rootSnapshot, resources[2].Attributes)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestIAMUsersPollerError(t *testing.T) {
	resetCache()
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAllError()

	IAMClientFunc = awstest.SetupMockIAM

	resources, marker, err := PollIAMUsers(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Timestamp:           &awstest.ExampleTime,
	})

	// Even though ListUsers will return no users, the poller will continue making API calls to build
	// the root user and error when building the credential report
	assert.Nil(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}
