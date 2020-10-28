package forwarder

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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sourceAPIModels "github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

// Test the caching mechanism
func TestSourceApiCache(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	testStreamHandler := StreamHandler{
		lambdaClient: mockClient,
	}

	testInput := &sourceAPIModels.LambdaInput{
		ListIntegrations: &sourceAPIModels.ListIntegrationsInput{
			IntegrationType: aws.String(sourceAPIModels.IntegrationTypeAWSScan),
		},
	}

	expectedInputPayload, err := jsoniter.Marshal(testInput)
	require.NoError(t, err)
	expectedInvokeInput := &lambda.InvokeInput{
		FunctionName: aws.String(sourceAPIFunctionName),
		Payload:      expectedInputPayload,
	}

	// We should only care about the integrationID and integrationLabel
	invokeResponesPayload := []*sourceAPIModels.SourceIntegration{
		{
			SourceIntegrationMetadata: sourceAPIModels.SourceIntegrationMetadata{
				IntegrationID:    "abc-123",
				IntegrationLabel: "Very Cool Very Legal Integration",
			},
		},
	}
	outputPayload, err := jsoniter.Marshal(invokeResponesPayload)
	require.NoError(t, err)

	expectedInvokeOutput := &lambda.InvokeOutput{
		ExecutedVersion: nil,
		FunctionError:   nil,
		LogResult:       nil,
		Payload:         outputPayload,
		StatusCode:      nil,
	}

	mockClient.On("Invoke", expectedInvokeInput).
		Return(expectedInvokeOutput, nil).Times(1)

	label, err := testStreamHandler.getIntegrationLabel(invokeResponesPayload[0].IntegrationID)
	assert.NoError(t, err)
	assert.Equal(t, invokeResponesPayload[0].IntegrationLabel, label)
	mockClient.AssertExpectations(t)

	// It should work a second time with no further mocking due to caching
	label, err = testStreamHandler.getIntegrationLabel(invokeResponesPayload[0].IntegrationID)
	assert.NoError(t, err)
	assert.Equal(t, invokeResponesPayload[0].IntegrationLabel, label)
	mockClient.AssertExpectations(t)

	// Now manually expire the cache, and it should try to make the call again
	lastUpdated = time.Now().Add(-2 * mappingAgeOut)
	mockClient.On("Invoke", expectedInvokeInput).
		Return(expectedInvokeOutput, nil).Times(1)
	label, err = testStreamHandler.getIntegrationLabel(invokeResponesPayload[0].IntegrationID)
	assert.NoError(t, err)
	assert.Equal(t, invokeResponesPayload[0].IntegrationLabel, label)
	mockClient.AssertExpectations(t)
}

// Test that missing labels work as expected
func TestSourceApiLabelNotFound(t *testing.T) {
	mockClient := &testutils.LambdaMock{}

	testInput := &sourceAPIModels.LambdaInput{
		ListIntegrations: &sourceAPIModels.ListIntegrationsInput{
			IntegrationType: aws.String(sourceAPIModels.IntegrationTypeAWSScan),
		},
	}

	expectedInputPayload, err := jsoniter.Marshal(testInput)
	require.NoError(t, err)
	expectedInvokeInput := &lambda.InvokeInput{
		FunctionName: aws.String(sourceAPIFunctionName),
		Payload:      expectedInputPayload,
	}

	invokeResponesPayload := []*sourceAPIModels.SourceIntegration{
		{
			SourceIntegrationMetadata: sourceAPIModels.SourceIntegrationMetadata{
				IntegrationID:    "abc-123",
				IntegrationLabel: "Very Cool Very Legal Integration",
			},
		},
	}
	outputPayload, err := jsoniter.Marshal(invokeResponesPayload)
	require.NoError(t, err)

	expectedInvokeOutput := &lambda.InvokeOutput{
		ExecutedVersion: nil,
		FunctionError:   nil,
		LogResult:       nil,
		Payload:         outputPayload,
		StatusCode:      nil,
	}

	mockClient.On("Invoke", expectedInvokeInput).
		Return(expectedInvokeOutput, nil).Times(1)

	testStreamHandler := StreamHandler{
		lambdaClient: mockClient,
	}

	label, err := testStreamHandler.getIntegrationLabel(invokeResponesPayload[0].IntegrationID + " slightly different")
	assert.Error(t, err)
	assert.Equal(t, "", label)
	mockClient.AssertExpectations(t)
}
