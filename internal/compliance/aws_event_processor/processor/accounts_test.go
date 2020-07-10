package processor

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

var (
	exampleAccounts = map[string]*models.SourceIntegration{
		"888888888888": {
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				AWSAccountID:     "888888888888",
				CreatedAtTime:    time.Now(),
				CreatedBy:        "96bad46d-2599-4926-a136-c6f4f7f3b1a3",
				IntegrationID:    "45c378a7-2e36-4b12-8e16-2d3c49ff1371",
				IntegrationLabel: "ProdAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
		},
		"111111111111": {
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				AWSAccountID:     "111111111111",
				CreatedAtTime:    time.Now(),
				CreatedBy:        "e049e3db-8c34-46c2-b5f2-8d01332a9921",
				IntegrationID:    "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
				IntegrationLabel: "TestAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
		},
	}

	exampleIntegrations = []*models.SourceIntegration{
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				AWSAccountID:     "888888888888",
				CreatedAtTime:    time.Now(),
				CreatedBy:        "96bad46d-2599-4926-a136-c6f4f7f3b1a3",
				IntegrationID:    "45c378a7-2e36-4b12-8e16-2d3c49ff1371",
				IntegrationLabel: "ProdAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				AWSAccountID:     "111111111111",
				CreatedAtTime:    time.Now(),
				CreatedBy:        "e049e3db-8c34-46c2-b5f2-8d01332a9921",
				IntegrationID:    "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
				IntegrationLabel: "TestAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
		},
	}

	exampleIntegrations2 = []*models.SourceIntegration{
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				AWSAccountID:     "888888888888",
				CreatedAtTime:    time.Now(),
				CreatedBy:        "96bad46d-2599-4926-a136-c6f4f7f3b1a3",
				IntegrationID:    "45c378a7-2e36-4b12-8e16-2d3c49ff1371",
				IntegrationLabel: "ProdAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				AWSAccountID:     "111111111111",
				CreatedAtTime:    time.Now(),
				CreatedBy:        "e049e3db-8c34-46c2-b5f2-8d01332a9921",
				IntegrationID:    "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
				IntegrationLabel: "StageAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 60,
			},
		},
		{
			SourceIntegrationMetadata: models.SourceIntegrationMetadata{
				AWSAccountID:     "333333333333",
				CreatedAtTime:    time.Now(),
				CreatedBy:        "96bad46d-2599-4926-a136-c6f4f7f3b1a3",
				IntegrationID:    "ce521962-1f30-4cdf-9c38-03be54fe5672",
				IntegrationLabel: "ProdAWS",
				IntegrationType:  models.IntegrationTypeAWSScan,
				ScanIntervalMins: 720,
			},
		},
	}
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
func (client *mockLambdaClient) Invoke(
	input *lambda.InvokeInput,
) (*lambda.InvokeOutput, error) {

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

func TestRefreshAccountsFromEmpty(t *testing.T) {
	mockLambda := &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations, 200), nil)
	lambdaClient = mockLambda

	require.Empty(t, accounts)
	err := refreshAccounts()
	require.NoError(t, err)
	assert.NotNil(t, accountsLastUpdated)
	assert.NotEmpty(t, accounts)
}

func TestRefreshAccounts(t *testing.T) {
	mockLambda := &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations, 200), nil)
	lambdaClient = mockLambda

	// Clear out the existing entries
	resetAccountCache()

	// Make the first call
	require.Empty(t, accounts)
	err := refreshAccounts()
	require.NoError(t, err)
	assert.NotEmpty(t, accounts)

	// Make the second call
	// Set the accounts last updated to 10 minutes ago
	accountsLastUpdated = time.Now().Add(time.Duration(-10) * time.Minute)
	// Reset the client with new output
	mockLambda = &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations2, 200), nil)
	lambdaClient = mockLambda

	err = refreshAccounts()
	require.NoError(t, err)
	assert.Len(t, accounts, 3)
}

func TestRefreshAccountsUseCache(t *testing.T) {
	mockLambda := &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations, 200), nil)
	lambdaClient = mockLambda

	// Clear out the existing entries
	resetAccountCache()

	// Make the first call
	require.Empty(t, accounts)
	err := refreshAccounts()
	require.NoError(t, err)
	assert.NotEmpty(t, accounts)

	// Make the second call
	// Set the accounts last updated to 1 minute ago
	accountsLastUpdated = time.Now().Add(time.Duration(-1) * time.Minute)
	// Reset the client with new output
	mockLambda = &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations2, 200), nil)
	lambdaClient = mockLambda

	err = refreshAccounts()
	require.NoError(t, err)
	assert.Len(t, accounts, 2)
}
