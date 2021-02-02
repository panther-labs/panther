package handlers

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
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/api/lambda/resources/models"
)

// Deleted resources are retained for 2 days in the database
const deleteWindowSecs = 2 * 24 * 60 * 60

// DeleteResources marks one or more resources as deleted.
func (API) DeleteResources(input *models.DeleteResourcesInput) *events.APIGatewayProxyResponse {
	deletes := make([]compliancemodels.DeleteStatusEntry, len(input.Resources))
	update := expression.
		Set(expression.Name("deleted"), expression.Value(true)).
		Set(expression.Name("expiresAt"), expression.Value(time.Now().Unix()+deleteWindowSecs))
	for i, entry := range input.Resources {
		deletes[i] = compliancemodels.DeleteStatusEntry{
			Resource: &compliancemodels.DeleteResource{ID: entry.ID},
		}

		// Dynamo does not support batch update, so these are sequential
		response := doUpdate(update, entry.ID)
		switch response.StatusCode {
		case http.StatusOK:
			continue
		case http.StatusNotFound:
			// If the resource wasn't found, log but we don't need to fail the operation.
			zap.L().Debug("resource no longer exists", zap.Any("deleteEntry", entry))
		default:
			return response // some other error condition
		}
	}

	// Delete affected compliance states
	zap.L().Info("deleting compliance status entries", zap.Int("itemCount", len(deletes)))
	lambdaInput := compliancemodels.LambdaInput{
		DeleteStatus: &compliancemodels.DeleteStatusInput{Entries: deletes},
	}
	if _, err := complianceClient.Invoke(&lambdaInput, nil); err != nil {
		zap.L().Error("failed to delete compliance status", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}
