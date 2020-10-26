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
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
)

const (
	maxWriteBackoff = time.Minute

	// Automatically expire status entries if they haven't been updated in 2 days.
	//
	// This handles edge cases where deleted policies/resources aren't fully cleared due to
	// eventual consistency, queue delays, etc.
	statusLifetime = 50 * time.Hour
)

// SetStatus batch writes a set of compliance status to the Dynamo table.
func (API) SetStatus(input *models.SetStatusInput) *events.APIGatewayProxyResponse {
	now := time.Now()
	expiresAt := now.Add(statusLifetime).Unix()
	writeRequests := make([]*dynamodb.WriteRequest, len(input.Entries))
	for i, entry := range input.Entries {
		newEntry := &models.ComplianceEntry{
			ErrorMessage:   entry.ErrorMessage,
			ExpiresAt:      expiresAt,
			IntegrationID:  entry.IntegrationID,
			LastUpdated:    now,
			PolicyID:       entry.PolicyID,
			PolicySeverity: entry.PolicySeverity,
			ResourceID:     entry.ResourceID,
			ResourceType:   entry.ResourceType,
			Status:         entry.Status,
			Suppressed:     entry.Suppressed,
		}

		marshaled, err := dynamodbattribute.MarshalMap(newEntry)
		if err != nil {
			err = fmt.Errorf("dynamodbattribute.MarshalMap failed: %s", err)
			zap.L().Error("SetStatus failed", zap.Error(err))
			return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		writeRequests[i] = &dynamodb.WriteRequest{PutRequest: &dynamodb.PutRequest{Item: marshaled}}
	}

	batchInput := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{Env.ComplianceTable: writeRequests},
	}

	if err := dynamodbbatch.BatchWriteItem(dynamoClient, maxWriteBackoff, batchInput); err != nil {
		err = fmt.Errorf("dynamodbbatch.BatchWriteItem failed: %s", err)
		zap.L().Error("SetStatus failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusCreated}
}
