package apihandlers

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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/remediation/models"
	"github.com/panther-labs/panther/internal/compliance/remediation_api/remediation"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// RemediateResource remediates a resource synchronously
func RemediateResource(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	remediateResource, errorResponse := checkRequest(request)
	if errorResponse != nil {
		return errorResponse
	}

	zap.L().Debug("invoking remediation synchronously")

	if err := invoker.Remediate(remediateResource); err != nil {
		if err == remediation.ErrNotFound {
			return gatewayapi.MarshalResponse(
				&models.Error{Message: aws.String(err.Error())}, http.StatusBadRequest)
		}
		if _, ok := err.(*genericapi.DoesNotExistError); ok {
			return gatewayapi.MarshalResponse(RemediationLambdaNotFound, http.StatusNotFound)
		}
		zap.L().Warn("failed to invoke remediation", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	zap.L().Debug("successfully invoked remediation",
		zap.Any("policyId", remediateResource.PolicyID),
		zap.Any("resourceId", remediateResource.ResourceID))
	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

// RemediateResourceAsync triggers remediation for a resource. The remediation is asynchronous
// so the method will return before the resource has been fixed, independently if it was
// successful or failed.
func RemediateResourceAsync(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	remediateResource, errorResponse := checkRequest(request)
	if errorResponse != nil {
		return errorResponse
	}

	zap.L().Debug("sending SQS message to trigger asynchronous remediation")

	sendMessageRequest := &sqs.SendMessageInput{
		MessageBody: aws.String(request.Body),
		QueueUrl:    aws.String(sqsQueueURL),
	}

	if _, err := sqsClient.SendMessage(sendMessageRequest); err != nil {
		zap.L().Warn("failed to send message", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	zap.L().Debug("successfully triggered asynchronous remediation",
		zap.Any("policyId", remediateResource.PolicyID),
		zap.Any("resourceId", remediateResource.ResourceID))
	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func checkRequest(request *events.APIGatewayProxyRequest) (*models.RemediateResource, *events.APIGatewayProxyResponse) {
	var remediateResource models.RemediateResource

	if err := jsoniter.UnmarshalFromString(request.Body, &remediateResource); err != nil {
		return nil, badRequest(aws.String("invalid request"))
	}

	if err := remediateResource.Validate(nil); err != nil {
		return nil, badRequest(aws.String(err.Error()))
	}

	return &remediateResource, nil
}
