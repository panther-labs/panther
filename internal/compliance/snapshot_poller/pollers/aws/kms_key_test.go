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

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestKMSKeyList(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvc([]string{"ListKeysPages"})

	out, marker, err := listKeys(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

// Test the iterator works on consecutive pages but stops at max page size
func TestKmskeyListIterator(t *testing.T) {
	var keys []*kms.KeyListEntry
	var marker *string

	cont := kmsKeyIterator(awstest.ExampleListKeysOutput, &keys, &marker)
	assert.True(t, cont)
	assert.Nil(t, marker)
	assert.Len(t, keys, 2)

	for i := 2; i < 50; i++ {
		cont = kmsKeyIterator(awstest.ExampleListKeysOutputContinue, &keys, &marker)
		assert.True(t, cont)
		assert.NotNil(t, marker)
		assert.Len(t, keys, i*2)
	}

	cont = kmsKeyIterator(awstest.ExampleListKeysOutputContinue, &keys, &marker)
	assert.False(t, cont)
	assert.NotNil(t, marker)
	assert.Len(t, keys, 100)
}

func TestKMSKeyListError(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvcError([]string{"ListKeysPages"})

	out, marker, err := listKeys(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestKMSKeyGetRotationStatus(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvc([]string{"GetKeyRotationStatus"})

	out, err := getKeyRotationStatus(mockSvc, awstest.ExampleKeyId)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestKMSKeyGetRotationStatusError(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvcError([]string{"GetKeyRotationStatus"})

	out, err := getKeyRotationStatus(mockSvc, awstest.ExampleKeyId)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestKMSKeyDescribe(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvc([]string{"DescribeKey"})

	out, err := describeKey(mockSvc, awstest.ExampleKeyId)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestKMSKeyDescribeError(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvcError([]string{"DescribeKey"})

	out, err := describeKey(mockSvc, awstest.ExampleKeyId)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestKMSKeyGetPolicy(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvc([]string{"GetKeyPolicy"})

	out, err := getKeyPolicy(mockSvc, awstest.ExampleKeyId)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestKMSKeyGetPolicyError(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvcError([]string{"GetKeyPolicy"})

	out, err := getKeyPolicy(mockSvc, awstest.ExampleKeyId)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestKMSKeyListResourceTags(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvc([]string{"ListResourceTags"})

	out, err := listResourceTags(mockSvc, awstest.ExampleKeyId)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestKMSKeyListResourceTagsError(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvcError([]string{"ListResourceTags"})

	out, err := listResourceTags(mockSvc, awstest.ExampleKeyId)
	require.Error(t, err)
	assert.Nil(t, out)
}

func TestBuildKmsKeySnapshotAWSManaged(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvc([]string{
		"GetKeyRotationStatus",
		"GetKeyPolicy",
		"ListResourceTags",
	})
	// Return the AWS managed example
	mockSvc.
		On("DescribeKey", mock.Anything).
		Return(awstest.ExampleDescribeKeyOutputAWSManaged, nil)
	awstest.MockKmsForSetup = mockSvc

	keySnapshot, err := buildKmsKeySnapshot(mockSvc, awstest.ExampleListKeysOutput.Keys[0])
	assert.NoError(t, err)
	assert.Nil(t, keySnapshot.KeyRotationEnabled)
	assert.NotEmpty(t, keySnapshot.KeyManager)
	assert.NotEmpty(t, keySnapshot.Policy)
}

func TestBuildKmsKeySnapshotErrors(t *testing.T) {
	mockSvc := awstest.BuildMockKmsSvcAllError()

	keySnapshot, err := buildKmsKeySnapshot(mockSvc, awstest.ExampleListKeysOutput.Keys[0])
	assert.Nil(t, keySnapshot)
	assert.Error(t, err)
}

func TestKMSKeyPoller(t *testing.T) {
	awstest.MockKmsForSetup = awstest.BuildMockKmsSvcAll()

	KmsClientFunc = awstest.SetupMockKms

	resources, marker, err := PollKmsKeys(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NotEmpty(t, resources)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestKMSKeyPollerError(t *testing.T) {
	resetCache()
	awstest.MockKmsForSetup = awstest.BuildMockKmsSvcAllError()

	KmsClientFunc = awstest.SetupMockKms

	resources, marker, err := PollKmsKeys(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	for _, event := range resources {
		assert.Nil(t, event.Attributes)
	}
	assert.Nil(t, marker)
	assert.Error(t, err)
}
