package remediation

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
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	policymodels "github.com/panther-labs/panther/api/gateway/analysis/models"
	remediationmodels "github.com/panther-labs/panther/api/lambda/remediation/models"
	resourcemodels "github.com/panther-labs/panther/api/lambda/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type mockLambdaClient struct {
	lambdaiface.LambdaAPI
	mock.Mock
}

func (m *mockLambdaClient) Invoke(input *lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*lambda.InvokeOutput), args.Error(1)
}

type mockRoundTripper struct {
	http.RoundTripper
	mock.Mock
}

func (m *mockRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	args := m.Called(request)
	return args.Get(0).(*http.Response), args.Error(1)
}

var (
	input = &remediationmodels.RemediateResourceInput{
		PolicyID:   "policyId",
		ResourceID: "resourceId",
	}

	remediation = &remediationmodels.ListRemediationsOutput{
		"AWS.S3.EnableBucketEncryption": map[string]interface{}{
			"SSEAlgorithm": "AES256",
		},
	}

	policy = &policymodels.Policy{
		AutoRemediationID: "AWS.S3.EnableBucketEncryption",
		AutoRemediationParameters: map[string]string{
			"SSEAlgorithm": "AES256",
		},
	}

	resourceAttributes = map[string]interface{}{
		"Region": "us-west-2",
	}

	resource = &resourcemodels.Resource{
		Attributes: resourceAttributes,
	}
)

func init() {
	policiesServiceHostname = "policiesServiceHostname"
	remediationLambdaArn = "arn:aws:lambda:us-west-2:123456789012:function:function"
}

func TestRemediate(t *testing.T) {
	mockResourcesClient := &gatewayapi.MockClient{}
	expectedGetResource := &resourcemodels.LambdaInput{
		GetResource: &resourcemodels.GetResourceInput{ID: "resourceId"},
	}
	mockResourcesClient.On("Invoke", expectedGetResource, &resourcemodels.Resource{}).Return(
		http.StatusOK, nil, resource)
	resourcesClient = mockResourcesClient

	// remediation lambda mock
	expectedPayload := Payload{
		RemediationID: string(policy.AutoRemediationID),
		Resource:      resourceAttributes,
		Parameters:    policy.AutoRemediationParameters,
	}
	expectedInput := LambdaInput{
		Action:  aws.String(remediationAction),
		Payload: expectedPayload,
	}
	expectedSerializedInput, err := jsoniter.Marshal(expectedInput)
	require.NoError(t, err)

	expectedLambdaInput := &lambda.InvokeInput{
		FunctionName: aws.String(remediationLambdaArn),
		Payload:      expectedSerializedInput,
	}

	mockClient := &mockLambdaClient{}
	mockClient.On("Invoke", expectedLambdaInput).Return(&lambda.InvokeOutput{}, nil)
	remediator := &Invoker{lambdaClient: mockClient}

	// analysis-api mock
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}
	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(policy, http.StatusOK), nil).Once()

	// run the function under test
	result := remediator.Remediate(input)

	// assert expectations
	assert.NoError(t, result)
	mockResourcesClient.AssertExpectations(t)
	mockClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func TestGetRemediations(t *testing.T) {
	mockClient := &mockLambdaClient{}
	remediator := &Invoker{
		lambdaClient: mockClient,
	}

	expectedInput := LambdaInput{Action: aws.String(listRemediationsAction)}
	expectedSerializedInput, _ := jsoniter.Marshal(expectedInput)

	expectedLambdaInput := &lambda.InvokeInput{
		FunctionName: aws.String(remediationLambdaArn),
		Payload:      expectedSerializedInput,
	}

	serializedRemediations := []byte("{\"AWS.S3.EnableBucketEncryption\": {\"SSEAlgorithm\": \"AES256\"}}")
	mockClient.On("Invoke", expectedLambdaInput).Return(&lambda.InvokeOutput{Payload: serializedRemediations}, nil)

	result, err := remediator.GetRemediations()
	assert.NoError(t, err)
	assert.Equal(t, remediation, result)
}

func TestRemediationNotFoundErrorIfNoRemediationConfigured(t *testing.T) {
	mockClient := &mockLambdaClient{}
	mockRoundTripper := &mockRoundTripper{}
	httpClient = &http.Client{Transport: mockRoundTripper}

	mockRemediatorLambdaClient := &mockLambdaClient{}
	remediator := &Invoker{
		lambdaClient: mockRemediatorLambdaClient,
	}

	policy := &policymodels.Policy{
		AutoRemediationID: "",
	}

	mockRoundTripper.On("RoundTrip", mock.Anything).Return(generateResponse(policy, http.StatusOK), nil).Once()

	result := remediator.Remediate(input)
	assert.Error(t, result)
	assert.Equal(t, ErrNotFound, result)

	mockClient.AssertExpectations(t)
	mockRoundTripper.AssertExpectations(t)
}

func generateResponse(body interface{}, httpCode int) *http.Response {
	serializedBody, _ := jsoniter.MarshalToString(body)
	return &http.Response{StatusCode: httpCode, Body: ioutil.NopCloser(strings.NewReader(serializedBody))}
}
