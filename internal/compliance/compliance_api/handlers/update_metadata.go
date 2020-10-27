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
	"path"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
)

// UpdateMetadata updates status entries for a given policy with a new severity / suppression set.
func (API) UpdateMetadata(input *models.UpdateMetadataInput) *events.APIGatewayProxyResponse {
	writes, errResponse := itemsToUpdate(input)
	if errResponse != nil {
		return errResponse
	}

	if len(writes) == 0 {
		// nothing to update
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
	}

	// It's faster to do a batch write with all of the updated entries instead of issuing
	// individual UPDATE calls for every item.
	batchInput := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{Env.ComplianceTable: writes},
	}

	if err := dynamodbbatch.BatchWriteItem(dynamoClient, maxWriteBackoff, batchInput); err != nil {
		err = fmt.Errorf("dynamodbbatch.BatchWriteItem failed: %s", err)
		zap.L().Error("UpdateMetadata failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func itemsToUpdate(input *models.UpdateMetadataInput) ([]*dynamodb.WriteRequest, *events.APIGatewayProxyResponse) {
	query, err := buildDescribePolicyQuery(input.PolicyID)
	if err != nil {
		zap.L().Error("UpdateMetadata failed", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	zap.L().Debug("querying items to update", zap.String("policyId", input.PolicyID))
	var writes []*dynamodb.WriteRequest
	err = queryPages(query, func(item *models.ComplianceEntry) error {
		ignored, patternErr := isIgnored(item.ResourceID, input.Suppressions)
		if patternErr != nil {
			return patternErr
		}

		// This status entry has changed - we need to rewrite it
		if item.Suppressed != ignored || item.PolicySeverity != input.Severity {
			item.PolicySeverity = input.Severity
			item.Suppressed = ignored

			marshalled, err := dynamodbattribute.MarshalMap(item)
			if err != nil {
				return err
			}

			writes = append(writes, &dynamodb.WriteRequest{
				PutRequest: &dynamodb.PutRequest{Item: marshalled},
			})
		}

		return nil
	})

	if err != nil {
		if err == path.ErrBadPattern {
			return nil, &events.APIGatewayProxyResponse{
				Body:       "invalid suppression pattern: " + err.Error(),
				StatusCode: http.StatusBadRequest,
			}
		}

		zap.L().Error("UpdateMetadata failed", zap.Error(err))
		return nil, &events.APIGatewayProxyResponse{
			Body:       err.Error(),
			StatusCode: http.StatusInternalServerError,
		}
	}

	return writes, nil
}
