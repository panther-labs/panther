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
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/gateway/remediation/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

func TestGetRemediations(t *testing.T) {
	mockInvoker := &mockInvoker{}
	invoker = mockInvoker

	request := &events.APIGatewayProxyRequest{
		QueryStringParameters: map[string]string{},
	}

	remediationsParameters := map[string]interface{}{
		"KMSMasterKeyID": "",
		"SSEAlgorithm":   "AES256",
	}
	remediations := &models.Remediations{
		"AWS.S3.EnableBucketEncryption": remediationsParameters,
	}

	mockInvoker.On("GetRemediations").Return(remediations, nil)

	expectedResponseBody := map[string]interface{}{"AWS.S3.EnableBucketEncryption": remediationsParameters}
	response := GetRemediations(request)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	var responseBody map[string]interface{}
	assert.NoError(t, jsoniter.UnmarshalFromString(response.Body, &responseBody))
	assert.Equal(t, expectedResponseBody, responseBody)
	mockInvoker.AssertExpectations(t)
}

func TestGetRemediationsLambdaDoesntExist(t *testing.T) {
	mockInvoker := &mockInvoker{}
	invoker = mockInvoker

	request := &events.APIGatewayProxyRequest{
		QueryStringParameters: map[string]string{},
	}

	mockInvoker.On("GetRemediations").Return(
		nil, &genericapi.DoesNotExistError{Message: "there is no aws remediation lambda configured for organization"})

	expectedResponseBody := &models.Error{Message: aws.String("Remediation Lambda not found or misconfigured")}
	response := GetRemediations(request)
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
	responseBody := &models.Error{}
	assert.NoError(t, jsoniter.UnmarshalFromString(response.Body, responseBody))
	assert.Equal(t, expectedResponseBody, responseBody)
	mockInvoker.AssertExpectations(t)
}
