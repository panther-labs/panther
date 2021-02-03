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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

// Unit tests
func TestAssumeRoleMissingParams(t *testing.T) {
	assert.Panics(t, func() { _ = assumeRole(nil, nil) })
}

func TestSingleResourceScanRegionIgnoreListError(t *testing.T) {
	var testIntegrationID = "0aab70c6-da66-4bb9-a83c-bbe8f5717fde"

	sampleScanRequest := &pollermodels.ScanEntry{
		AWSAccountID:     aws.String("123456789012"),
		IntegrationID:    aws.String(testIntegrationID),
		Region:           aws.String("us-west-2"),
		ResourceType:     aws.String(awsmodels.KmsKeySchema),
		RegionIgnoreList: []string{"us-west-2"},
		ResourceID:       aws.String("arn:aws:kms:us-west-2::test"),
	}

	sampleResourcePollerInput := &awsmodels.ResourcePollerInput{
		IntegrationID:    aws.String(testIntegrationID),
		Region:           aws.String("us-west-2"),
		Timestamp:        &awstest.ExampleTime,
		RegionIgnoreList: []string{"us-west-2"},
	}

	awstest.MockKmsForSetup = awstest.BuildMockKmsSvcAll()

	RateLimitTracker, _ = lru.NewARC(10)
	KmsClientFunc = awstest.SetupMockKms

	// Provide stub poller session
	SnapshotPollerSession = &session.Session{}

	_, err := singleResourceScan(sampleScanRequest, sampleResourcePollerInput)

	assert.NoError(t, err)
}

func TestSingleResourceScanGenericError(t *testing.T) {
	// This tests the snapshot-poller singleResourceScan case of generic errors
	// Addresses the case for the interface conversion panic issue seen in production
	var testIntegrationID = "0aab70c6-da66-4bb9-a83c-bbe8f5717fde"

	sampleScanRequest := &pollermodels.ScanEntry{
		AWSAccountID:  aws.String("123456789012"),
		IntegrationID: aws.String(testIntegrationID),
		Region:        aws.String("us-west-2"),
		ResourceType:  aws.String(awsmodels.KmsKeySchema),
		ResourceID:    aws.String("arn:aws:kms:us-west-2::test"),
	}

	sampleResourcePollerInput := &awsmodels.ResourcePollerInput{
		IntegrationID: aws.String(testIntegrationID),
		Region:        aws.String("us-west-2"),
		Timestamp:     &awstest.ExampleTime,
	}

	awstest.MockKmsForSetup = awstest.BuildMockKmsSvcError([]string{"DescribeKey"})

	RateLimitTracker, _ = lru.NewARC(10)
	KmsClientFunc = awstest.SetupMockKms

	genericError := errors.New("generic error")

	mockKmsClient := &awstest.MockKms{}
	mockKmsClient.On("DescribeKey", &kms.DescribeKeyInput{}).Return(nil, genericError)

	// Provide stub poller session
	SnapshotPollerSession = &session.Session{}

	_, err := singleResourceScan(sampleScanRequest, sampleResourcePollerInput)

	assert.Error(t, errors.Wrapf(
		genericError,
		"could not scan aws resource: %s, in account: %s",
		aws.StringValue(sampleScanRequest.ResourceID),
		aws.StringValue(sampleScanRequest.AWSAccountID),
	), err)
}
