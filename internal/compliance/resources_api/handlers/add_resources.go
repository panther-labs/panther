package handlers

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/resources/models"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const maxBackoff = 30 * time.Second

// AddResources batch writes a group of resources to the Dynamo table.
func AddResources(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseAddResources(request)
	if err != nil {
		return badRequest(err)
	}

	now := models.LastModified(time.Now())
	writeRequests := make([]*dynamodb.WriteRequest, len(input.Resources))
	sqsEntries := make([]*sqs.SendMessageBatchRequestEntry, len(input.Resources))
	for i, r := range input.Resources {
		item := resourceItem{
			Attributes:      r.Attributes,
			Deleted:         false,
			ID:              r.ID,
			IntegrationID:   r.IntegrationID,
			IntegrationType: r.IntegrationType,
			LastModified:    now,
			Type:            r.Type,
			LowerID:         strings.ToLower(string(r.ID)),
		}

		marshalled, err := dynamodbattribute.MarshalMap(item)
		if err != nil {
			zap.L().Error("dynamodbattribute.MarshalMap failed", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		writeRequests[i] = &dynamodb.WriteRequest{PutRequest: &dynamodb.PutRequest{Item: marshalled}}

		body, err := jsoniter.MarshalToString(item.Resource(""))
		if err != nil {
			zap.L().Error("jsoniter.MarshalToString(resource) failed", zap.Error(err))
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		sqsEntries[i] = &sqs.SendMessageBatchRequestEntry{
			Id:          aws.String(strconv.Itoa(i)),
			MessageBody: aws.String(body),
		}
	}

	dynamoInput := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{env.ResourcesTable: writeRequests},
	}
	if err := dynamodbbatch.BatchWriteItem(dynamoClient, maxBackoff, dynamoInput); err != nil {
		zap.L().Error("dynamodbbatch.BatchWriteItem failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	sqsInput := &sqs.SendMessageBatchInput{
		Entries:  sqsEntries,
		QueueUrl: &env.ResourcesQueueURL,
	}
	if failures, err := sqsbatch.SendMessageBatch(sqsClient, maxBackoff, sqsInput); err != nil {
		if _, ok := err.(sqsbatch.MessageTooBigError); ok {

		}
		zap.L().Error("sqsbatch.SendMessageBatch failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusCreated}
}

// Parse the request body into the input model.
func parseAddResources(request *events.APIGatewayProxyRequest) (*models.AddResources, error) {
	var result models.AddResources
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	// Swagger doesn't validate plain objects
	for i, resource := range result.Resources {
		if len(resource.Attributes.(map[string]interface{})) == 0 {
			return nil, fmt.Errorf("resources[%d].attributes cannot be empty", i)
		}
	}

	return &result, result.Validate(nil)
}
