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
	"testing"

	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/remediation/models"
)

type mockSqsClient struct {
	sqsiface.SQSAPI
	mock.Mock
}

func (m *mockSqsClient) SendMessage(input *sqs.SendMessageInput) (*sqs.SendMessageOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SendMessageOutput), args.Error(1)
}

var input = &models.RemediateResourceInput{
	PolicyID:   "policyId",
	ResourceID: "resourceId",
}

func TestRemediateResource(t *testing.T) {
	mockInvoker := &mockInvoker{}
	invoker = mockInvoker
	mockSqsClient := &mockSqsClient{}
	sqsClient = mockSqsClient

	mockInvoker.On("Remediate", input).Return(nil)

	response := API{}.RemediateResource(input)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "", response.Body)
	mockInvoker.AssertExpectations(t)
	mockSqsClient.AssertExpectations(t)
}

func TestRemediateResourceAsync(t *testing.T) {
	mockInvoker := &mockInvoker{}
	invoker = mockInvoker
	mockSqsClient := &mockSqsClient{}
	sqsClient = mockSqsClient
	sqsQueueURL = "sqsQueueURL"

	mockSqsClient.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, nil)

	response := API{}.RemediateResourceAsync(input)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "", response.Body)
	mockInvoker.AssertExpectations(t)
	mockSqsClient.AssertExpectations(t)
}
