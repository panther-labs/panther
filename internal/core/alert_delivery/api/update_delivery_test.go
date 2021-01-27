package api

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

	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	alertModels "github.com/panther-labs/panther/api/lambda/alerts/models"
	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestUpdateAlerts(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	alertID := "alert-id"
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}
	dispatchedAt := time.Now().UTC()

	statuses := []DispatchStatus{
		{
			Alert: deliverymodel.Alert{
				AlertID:   &alertID,
				Type:      deliverymodel.RuleType,
				OutputIds: outputIds,
				Severity:  "INFO",
				CreatedAt: time.Now().UTC(),
			},
			OutputID:     outputIds[0],
			Message:      "success",
			StatusCode:   200,
			Success:      true,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},
		{
			Alert: deliverymodel.Alert{
				AlertID:   &alertID,
				Type:      deliverymodel.PolicyType,
				OutputIds: outputIds,
				Severity:  "INFO",
				CreatedAt: time.Now().UTC(),
			},
			OutputID:     outputIds[1],
			Message:      "failure",
			StatusCode:   401,
			Success:      false,
			NeedsRetry:   true,
			DispatchedAt: dispatchedAt,
		},
		{
			Alert: deliverymodel.Alert{
				AlertID:   &alertID,
				Type:      deliverymodel.RuleType,
				OutputIds: outputIds,
				Severity:  "INFO",
				CreatedAt: time.Now().UTC(),
			},
			OutputID:     outputIds[2],
			Message:      "failure",
			StatusCode:   500,
			Success:      false,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},
	}

	deliveryResponses := []*alertModels.DeliveryResponse{
		{
			OutputID:     outputIds[0],
			Message:      "success",
			StatusCode:   200,
			Success:      true,
			DispatchedAt: dispatchedAt,
		},
		{
			OutputID:     outputIds[1],
			Message:      "failure",
			StatusCode:   401,
			Success:      false,
			DispatchedAt: dispatchedAt,
		},
		{
			OutputID:     outputIds[2],
			Message:      "failure",
			StatusCode:   500,
			Success:      false,
			DispatchedAt: dispatchedAt,
		},
	}
	expectedResponse := []*alertModels.AlertSummary{
		{
			AlertID:           "alert-id",
			DeliveryResponses: deliveryResponses,
		},
	}

	expectedLambdaResponse := alertModels.AlertSummary{
		AlertID:           alertID,
		DeliveryResponses: deliveryResponses,
	}

	payload, err := jsoniter.Marshal(expectedLambdaResponse)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Times(1)

	response := updateAlerts(statuses)
	assert.Equal(t, expectedResponse, response)
	mockClient.AssertExpectations(t)
}

func TestUpdateAlert(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	ch := make(chan alertModels.AlertSummary, 1)

	alertID := "alert-id"
	dispatchedAt := time.Now().UTC()
	deliveryResponses := []*alertModels.DeliveryResponse{
		{
			OutputID:     "output-id-1",
			Message:      "success",
			StatusCode:   200,
			Success:      true,
			DispatchedAt: dispatchedAt,
		},
		{
			OutputID:     "output-id-2",
			Message:      "failure",
			StatusCode:   401,
			Success:      false,
			DispatchedAt: dispatchedAt,
		},
		{
			OutputID:     "output-id-3",
			Message:      "failure",
			StatusCode:   500,
			Success:      false,
			DispatchedAt: dispatchedAt,
		},
	}

	expectedResponse := alertModels.AlertSummary{
		AlertID:           alertID,
		DeliveryResponses: deliveryResponses,
	}

	payload, err := jsoniter.Marshal(expectedResponse)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	go updateAlert(alertID, deliveryResponses, ch)
	response := <-ch
	assert.Equal(t, expectedResponse, response)
	mockClient.AssertExpectations(t)
}
