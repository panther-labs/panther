package gatewayapi

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
