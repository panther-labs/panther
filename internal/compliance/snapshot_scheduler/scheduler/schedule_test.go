package scheduler

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
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/box"
)

//
// Mocks
//

// mockLambdaClient mocks the API calls to the snapshot-api.
type mockLambdaClient struct {
	lambdaiface.LambdaAPI
	mock.Mock
}

// Invoke is a mock method to invoke a Lambda function.
func (client *mockLambdaClient) Invoke(input *lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*lambda.InvokeOutput), args.Error(1)
}

//
// Helpers
//

// getTestInvokeInput returns an example Lambda.Invoke input for the SnapshotAPI.
func getTestInvokeInput() *lambda.InvokeInput {
	input := &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{
			IntegrationType: aws.String("aws-scan"),
		},
	}
	payload, err := jsoniter.Marshal(input)
	if err != nil {
		panic(err)
	}

	return &lambda.InvokeInput{
		FunctionName: aws.String("panther-source-api"),
		Payload:      payload,
	}
}

// getTestInvokeOutput returns an example Lambda.Invoke response from the SnapshotAPI.
func getTestInvokeOutput(payload interface{}, statusCode int64) *lambda.InvokeOutput {
	payloadBytes, err := jsoniter.Marshal(payload)
	if err != nil {
		panic(err)
	}

	return &lambda.InvokeOutput{
		Payload:    payloadBytes,
		StatusCode: aws.Int64(statusCode),
	}
}

//
// Unit Tests
//

var (
	exampleIntegrations = []*models.SourceIntegration{
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "45c378a7-2e36-4b12-8e16-2d3c49ff1371",
				IntegrationLabel: "ProdAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
			SourceIntegrationStatus: models.SourceIntegrationStatus{
				ScanStatus: models.StatusOK,
			},
			SourceIntegrationScanInformation: models.SourceIntegrationScanInformation{
				LastScanEndTime:   box.Time(time.Now().Add(time.Duration(-15) * time.Minute)),
				LastScanStartTime: box.Time(time.Now().Add(time.Duration(-20) * time.Minute)),
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
				IntegrationLabel: "TestAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 30,
			},
			SourceIntegrationStatus: models.SourceIntegrationStatus{
				ScanStatus: models.StatusOK,
			},
			SourceIntegrationScanInformation: models.SourceIntegrationScanInformation{
				LastScanEndTime:   box.Time(time.Now().Add(time.Duration(-35) * time.Minute)),
				LastScanStartTime: box.Time(time.Now().Add(time.Duration(-40) * time.Minute)),
			},
		},
		// A new integration that was recently added that has never been scanned.
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
				IntegrationLabel: "TestAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 30,
			},
		},
		// An integration with a scan in progress, started 20 minutes ago.
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "9a171500-7794-4aaa-8b4a-19ce8e9ba4fb",
				IntegrationLabel: "Staging AWS Account",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
			SourceIntegrationStatus: models.SourceIntegrationStatus{
				ScanStatus: models.StatusScanning,
			},
			SourceIntegrationScanInformation: models.SourceIntegrationScanInformation{
				LastScanStartTime: box.Time(time.Now().Add(time.Duration(-20) * time.Minute)),
			},
		},
		// An integration with a scan in progress, stuck.
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				IntegrationID:    "2654cf7a-a13a-4b9b-8b4d-f3e5bfc51cb4",
				IntegrationLabel: "Development AWS Account",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
			SourceIntegrationStatus: models.SourceIntegrationStatus{
				ScanStatus: models.StatusScanning,
			},
			SourceIntegrationScanInformation: models.SourceIntegrationScanInformation{
				LastScanStartTime: box.Time(time.Now().Add(time.Duration(-65) * time.Minute)),
				// Last time it scanned was a day ago.
				LastScanEndTime: box.Time(time.Now().Add(time.Duration(-24) * time.Hour)),
			},
		},
	}
)

func TestPollAndIssueNewScansNoneToRun(t *testing.T) {
	mockLambda := &mockLambdaClient{}

	mockLambda.
		On("Invoke", mock.Anything).
		// Pass in the first integration, which won't need a new scan.
		Return(getTestInvokeOutput(exampleIntegrations[:1], 200), nil)
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		// Pass in the first integration, which won't need a new scan.
		Return(getTestInvokeOutput(exampleIntegrations[:1], 200), nil)
	lambdaClient = mockLambda

	result := PollAndIssueNewScans()

	mockLambda.AssertExpectations(t)
	assert.NoError(t, result)
}

func TestPollAndIssueNewScansZeroIntegrations(t *testing.T) {
	mockLambda := &mockLambdaClient{}
	var emptyOutput []*models.SourceIntegration

	mockLambda.
		On("Invoke", getTestInvokeInput()).
		// Pass in the first integration, which won't need a new scan.
		Return(getTestInvokeOutput(emptyOutput, 200), nil)
	lambdaClient = mockLambda

	result := PollAndIssueNewScans()

	mockLambda.AssertExpectations(t)
	assert.NoError(t, result)
}

func TestScanIntervalElapsed(t *testing.T) {
	assert.True(t, scanIntervalElapsed(&models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			ScanIntervalMins: 30,
		},
		SourceIntegrationScanInformation: models.SourceIntegrationScanInformation{
			LastScanEndTime: box.Time(time.Now().Add(time.Duration(-60) * time.Minute)),
		},
	}))
}

func TestNewScanNotNeeded(t *testing.T) {
	assert.False(t, scanIntervalElapsed(&models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			ScanIntervalMins: 30,
		},
		SourceIntegrationScanInformation: models.SourceIntegrationScanInformation{
			LastScanEndTime: box.Time(time.Now().Add(time.Duration(-15) * time.Minute)),
		},
	}))
}

func TestScanIsNotOngoingScanning(t *testing.T) {
	assert.False(t, scanIsNotOngoing(&models.SourceIntegration{
		SourceIntegrationStatus: models.SourceIntegrationStatus{
			ScanStatus: models.StatusScanning,
		},
	}))
}

func TestScanIsNotOngoingOK(t *testing.T) {
	assert.True(t, scanIsNotOngoing(&models.SourceIntegration{
		SourceIntegrationStatus: models.SourceIntegrationStatus{
			ScanStatus: models.StatusOK,
		},
	}))
}

func TestGetEnabledIntegrations(t *testing.T) {
	mockLambda := new(mockLambdaClient)
	lambdaClient = mockLambda

	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations, 200), nil)

	integrations, err := GetEnabledIntegrations()

	mockLambda.AssertExpectations(t)
	require.NoError(t, err)
	assert.Len(t, integrations, len(exampleIntegrations))
}

func TestGetEnabledIntegrationsError(t *testing.T) {
	mockLambda := new(mockLambdaClient)
	lambdaClient = mockLambda

	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(&lambda.InvokeOutput{}, errors.New("fake error"))

	_, err := GetEnabledIntegrations()

	mockLambda.AssertExpectations(t)
	require.Error(t, err)
}
