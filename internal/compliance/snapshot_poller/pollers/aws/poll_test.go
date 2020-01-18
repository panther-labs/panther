package aws

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

var (
	testGetCallerIdentityOutput = &sts.GetCallerIdentityOutput{
		Account: aws.String("111111111111"),
		Arn:     aws.String("arn:aws:iam::account-id:role/role-name"),
		UserId:  aws.String("mockUserId"),
	}
)

func configureMockSTSClientWithError(code, message string) *awstest.MockSTS {
	mockStsClient := &awstest.MockSTS{}
	mockStsClient.
		On("GetCallerIdentity", &sts.GetCallerIdentityInput{}).
		Return(
			testGetCallerIdentityOutput,
			awserr.New(code, message, errors.New("fake sts error")),
		)
	return mockStsClient
}

func configureMockSTSClientNoError() *awstest.MockSTS {
	mockStsClient := &awstest.MockSTS{}
	mockStsClient.
		On("GetCallerIdentity", &sts.GetCallerIdentityInput{}).
		Return(
			testGetCallerIdentityOutput,
			nil,
		)
	return mockStsClient
}

// Unit tests

func TestAssumeRole(t *testing.T) {
	AssumeRoleProviderFunc = awstest.STSAssumeRoleProviderMock
	STSClientFunc = awstest.SetupMockSTSClient
	awstest.MockSTSForSetup = configureMockSTSClientNoError()

	testSess, err := session.NewSession()
	require.NoError(t, err)

	creds, err := AssumeRole(
		&awsmodels.ResourcePollerInput{
			AuthSource:          &awstest.ExampleAuthSource,
			AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
			IntegrationID:       awstest.ExampleIntegrationID,
			Timestamp:           &awstest.ExampleTime,
		},
		testSess,
	)

	require.NoError(t, err)
	assert.NotEmpty(t, creds)
}

func TestAssumeRoleVerifyFailure(t *testing.T) {
	AssumeRoleProviderFunc = awstest.STSAssumeRoleProviderMock
	STSClientFunc = awstest.SetupMockSTSClient
	awstest.MockSTSForSetup = configureMockSTSClientWithError("AccessDenied", "You shall not pass")

	testSess, err := session.NewSession()
	require.NoError(t, err)

	creds, err := AssumeRole(
		&awsmodels.ResourcePollerInput{
			AuthSource:          &awstest.ExampleAuthSource,
			AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
			IntegrationID:       awstest.ExampleIntegrationID,
			Timestamp:           &awstest.ExampleTime,
		},
		testSess,
	)

	require.Error(t, err)
	assert.Nil(t, creds)
}

func TestAssumeRoleAddToCache(t *testing.T) {
	AssumeRoleProviderFunc = awstest.STSAssumeRoleProviderMock
	STSClientFunc = awstest.SetupMockSTSClient
	awstest.MockSTSForSetup = configureMockSTSClientNoError()

	// reset the cache for this test
	CredentialCache = make(map[string]*credentials.Credentials)

	testSess, err := session.NewSession()
	require.NoError(t, err)

	creds, err := AssumeRole(
		&awsmodels.ResourcePollerInput{
			AuthSource:          &awstest.ExampleAuthSource,
			AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
			IntegrationID:       aws.String("integration-id"),
			Timestamp:           &awstest.ExampleTime,
		},
		testSess,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, creds)

	creds, err = AssumeRole(
		&awsmodels.ResourcePollerInput{
			AuthSource:          &awstest.ExampleAuthSource2,
			AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
			IntegrationID:       aws.String("integration-id"),
			Timestamp:           &awstest.ExampleTime,
		},
		testSess,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, creds)

	assert.Len(t, CredentialCache, 2)
	assert.Contains(t, CredentialCache, awstest.ExampleAuthSource)
	assert.Contains(t, CredentialCache, awstest.ExampleAuthSource2)
}

func TestAssumeRoleNilSession(t *testing.T) {
	AssumeRoleProviderFunc = awstest.STSAssumeRoleProviderMock
	STSClientFunc = awstest.SetupMockSTSClient
	awstest.MockSTSForSetup = configureMockSTSClientNoError()

	creds, err := AssumeRole(
		&awsmodels.ResourcePollerInput{
			AuthSource:          &awstest.ExampleAuthSource,
			AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
			IntegrationID:       awstest.ExampleIntegrationID,
			Timestamp:           &awstest.ExampleTime,
		},
		nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, creds)
}

func TestAssumeRoleMissingParams(t *testing.T) {
	AssumeRoleProviderFunc = awstest.STSAssumeRoleProviderMock
	assert.Panics(t, func() { _, _ = AssumeRole(nil, nil) })
}

func TestVerifyAssumedCreds(t *testing.T) {
	STSClientFunc = awstest.SetupMockSTSClient
	awstest.MockSTSForSetup = configureMockSTSClientNoError()

	err := verifyAssumedCreds(&credentials.Credentials{})
	require.NoError(t, err)
}

func TestVerifyAssumedCredsAccessDeniedError(t *testing.T) {
	STSClientFunc = awstest.SetupMockSTSClient
	awstest.MockSTSForSetup = configureMockSTSClientWithError("AccessDenied", "You shall not pass")

	err := verifyAssumedCreds(&credentials.Credentials{})
	require.Error(t, err)
}

func TestVerifyAssumedCredsOtherError(t *testing.T) {
	STSClientFunc = awstest.SetupMockSTSClient
	awstest.MockSTSForSetup = configureMockSTSClientWithError("Error", "Something went wrong")

	err := verifyAssumedCreds(&credentials.Credentials{})
	// It's just logged
	require.NoError(t, err)
}
