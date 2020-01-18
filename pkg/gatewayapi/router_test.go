package gatewayapi

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type responseModel struct {
	Counts map[string]int `json:"counts"`
	Name   string         `json:"name"`
	Tags   []string       `json:"tags"`
}

var (
	testContext = lambdacontext.NewContext(
		context.Background(), &lambdacontext.LambdaContext{AwsRequestID: "test-request-id"})

	handler = LambdaProxy(map[string]RequestHandler{
		"DELETE /":                 panicPanther,
		"GET /panthers":            listPanthers,
		"POST /panthers":           newPanther,
		"DELETE /panthers/{catId}": deletePanther,
	})
)

func panicPanther(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	panic("at the disco")
}

func listPanthers(*events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func newPanther(*events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
}

func deletePanther(*events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
}

func TestLambdaProxyPanic(t *testing.T) {
	result, err := handler(testContext, &events.APIGatewayProxyRequest{HTTPMethod: "DELETE", Path: "/", Resource: "/"})
	require.Nil(t, err)
	assert.Equal(t, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, result)
}

func TestLambdaProxyNotImplemented(t *testing.T) {
	result, err := handler(testContext, &events.APIGatewayProxyRequest{
		HTTPMethod: "GET", Path: "/panthers/jaguar", Resource: "/panthers/{catId}"})
	require.Nil(t, err)
	assert.Equal(t, &events.APIGatewayProxyResponse{StatusCode: http.StatusNotImplemented}, result)
}

func TestLambdaProxySuccess(t *testing.T) {
	result, err := handler(testContext, &events.APIGatewayProxyRequest{
		HTTPMethod: "GET", Path: "/panthers", Resource: "/panthers"})
	require.Nil(t, err)
	assert.Equal(t, &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, result)
}

func TestLambdaProxyClientError(t *testing.T) {
	result, err := handler(testContext, &events.APIGatewayProxyRequest{
		HTTPMethod: "DELETE", Path: "/panthers/jaguar", Resource: "/panthers/{catId}"})
	require.Nil(t, err)
	assert.Equal(t, &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}, result)
}

func TestLambdaProxyServerError(t *testing.T) {
	result, err := handler(testContext, &events.APIGatewayProxyRequest{
		HTTPMethod: "POST", Path: "/panthers", Resource: "/panthers"})
	require.Nil(t, err)
	assert.Equal(t, &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, result)
}

func TestMarshalResponse(t *testing.T) {
	result := MarshalResponse(&responseModel{Name: "Panther Labs"}, http.StatusOK)
	expected := &events.APIGatewayProxyResponse{
		Body:       `{"counts":{},"name":"Panther Labs","tags":[]}`,
		StatusCode: http.StatusOK,
	}
	assert.Equal(t, expected, result)
}
