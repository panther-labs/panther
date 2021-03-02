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
	"errors"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/api/lambda/resources/models"
)

// The resource struct stored in Dynamo has some different fields compared to the external models.Resource
type resourceItem struct {
	Attributes      interface{} `json:"attributes"`
	Deleted         bool        `json:"deleted"`
	ID              string      `json:"id"`
	IntegrationID   string      `json:"integrationId"`
	IntegrationType string      `json:"integrationType"`
	LastModified    time.Time   `json:"lastModified"`
	Type            string      `json:"type"`

	// Internal fields: TTL and more efficient filtering
	ExpiresAt int64  `json:"expiresAt,omitempty"`
	LowerID   string `json:"lowerId"` // lowercase ID for efficient ID substring filtering
}

// Convert dynamo item to external models.Resource
func (r *resourceItem) Resource(status compliancemodels.ComplianceStatus) models.Resource {
	return models.Resource{
		Attributes:       r.Attributes,
		ComplianceStatus: status,
		Deleted:          r.Deleted,
		ID:               r.ID,
		IntegrationID:    r.IntegrationID,
		IntegrationType:  r.IntegrationType,
		LastModified:     r.LastModified,
		Type:             r.Type,
	}
}

// Build the table key in the format Dynamo expects
func tableKey(resourceID string) map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"id": {S: &resourceID},
	}
}

// Build a condition expression if the resource must exist in the table
func existsCondition(resourceID string) expression.ConditionBuilder {
	return expression.Name("id").Equal(expression.Value(resourceID))
}

// Complete a conditional Dynamo update and return the appropriate status code
func doUpdate(update expression.UpdateBuilder, resourceID string) *events.APIGatewayProxyResponse {
	condition := existsCondition(resourceID)
	expr, err := expression.NewBuilder().WithCondition(condition).WithUpdate(update).Build()
	if err != nil {
		zap.L().Error("expr.Build failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	zap.L().Debug("submitting dynamo item update",
		zap.String("resourceId", resourceID))
	_, err = dynamoClient.UpdateItem(&dynamodb.UpdateItemInput{
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key:                       tableKey(resourceID),
		TableName:                 &env.ResourcesTable,
		UpdateExpression:          expr.Update(),
	})

	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
		}
		zap.L().Error("dynamoClient.UpdateItem failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

type scanResult struct {
	resources []models.Resource
	err       error
}

// Wrapper around dynamoClient.ScanPages that accepts a handler function to process each item.
func scanPages(inputs []*dynamodb.ScanInput, includeCompliance bool,
	requiredComplianceStatus compliancemodels.ComplianceStatus) ([]models.Resource, error) {

	results := make(chan scanResult)
	defer close(results)
	// The scan inputs have already been broken up into segments, scan each segment in parallel
	for _, scanInput := range inputs {
		go func(input *dynamodb.ScanInput) {
			// Recover from panic so we don't block forever when waiting for routines to finish.
			defer func() {
				if r := recover(); r != nil {
					zap.L().Error("panicked while scanning segment",
						zap.Any("segment", input.Segment), zap.Any("panic", r))
					results <- scanResult{nil, errors.New("panicked goroutine")}
				}
			}()

			// Scan this segment
			var segmentResources []models.Resource
			var handlerErr, unmarshalErr error
			// The pages of this segment will be handled serially
			err := dynamoClient.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
				var items []*resourceItem
				if unmarshalErr = dynamodbattribute.UnmarshalListOfMaps(page.Items, &items); unmarshalErr != nil {
					return false // stop paginating
				}

				if !includeCompliance {
					for _, entry := range items {
						segmentResources = append(segmentResources, entry.Resource(""))
					}
					return true
				}

				if requiredComplianceStatus == "" {
					for _, entry := range items {
						var status *complianceStatus
						status, handlerErr = getComplianceStatus(entry.ID)
						if handlerErr != nil {
							return false
						}
						segmentResources = append(segmentResources, entry.Resource(status.Status))
					}
					return true
				}

				for _, entry := range items {
					var status *complianceStatus
					status, handlerErr = getComplianceStatus(entry.ID)
					if handlerErr != nil {
						return false
					}
					// Filter on the compliance status (if applicable)
					if requiredComplianceStatus == status.Status {
						// Resource passed all of the filters - add it to the result set
						segmentResources = append(segmentResources, entry.Resource(status.Status))
					}
				}
				return true // keep paging
			})

			if handlerErr != nil {
				zap.L().Error("query item handler failed", zap.Error(handlerErr))
				results <- scanResult{nil, handlerErr}
			}

			if unmarshalErr != nil {
				zap.L().Error("dynamodbattribute.UnmarshalListOfMaps failed", zap.Error(unmarshalErr))
				results <- scanResult{nil, unmarshalErr}
			}

			if err != nil {
				zap.L().Error("dynamoClient.QueryPages failed", zap.Error(err))
				results <- scanResult{nil, err}
			}

			// Report results
			results <- scanResult{
				resources: segmentResources,
				err:       nil,
			}
		}(scanInput)
	}

	// Merge scan results
	zap.L().Debug("scans initiated, awaiting results")
	var err error
	var mergedResources []models.Resource
	for range inputs {
		result := <-results
		zap.L().Debug("received scan segment results", zap.Any("results", len(result.resources)), zap.Error(result.err))
		if result.err != nil {
			err = result.err
			continue
		}
		mergedResources = append(mergedResources, result.resources...)
	}

	return mergedResources, err
}
