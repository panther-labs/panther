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
	"log"
	"net/http"
	"runtime/debug"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

// RequestHandler is a function which handles an HTTP request for a single method/resource pair.
type RequestHandler = func(*events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse

// LambdaProxy generates a handler function for API Gateway lambda-proxy backends.
//
// Note: The returned error is always nil. All errors should be reported in the status code of the response.
func LambdaProxy(methodHandlers map[string]RequestHandler) func(
	context.Context, *events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {

	return func(
		ctx context.Context,
		input *events.APIGatewayProxyRequest,
	) (result *events.APIGatewayProxyResponse, unusedErr error) {
		defer func() {
			// If there is a panic, log it and return gracefully (InternalServerError)
			// NOTE: the zap logger may not exist yet (the logger creation can panic)
			if r := recover(); r != nil {
				log.Println("ERROR: recovered from panic:", r)
				debug.PrintStack()
				result = &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
			}
		}()

		lc, _ := lambdalogger.ConfigureGlobal(ctx, map[string]interface{}{
			"requestMethod":          input.HTTPMethod, // e.g. GET
			"requestPathParameters":  input.PathParameters,
			"requestQueryParameters": input.QueryStringParameters,
			"requestResource":        input.Resource, // e.g. /orgs/{orgId}/accounts/{accountType}
		})

		methodKey := input.HTTPMethod + " " + input.Resource

		operation := oplog.NewManager("admin", lc.InvokedFunctionArn).Start(methodKey).WithMemUsed(lambdacontext.MemoryLimitInMB)

		handler, ok := methodHandlers[methodKey]
		if !ok {
			operation.Stop().LogError(errors.New("unexpected method/resource"))
			// IMPORTANT: do not return any err, result handling manages that
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotImplemented}, nil
		}

		result = handler(input)

		switch {
		case result.StatusCode < 400:
			operation.Stop().LogSuccess(zap.Int("statusCode", result.StatusCode), zap.Int("bodyLength", len(result.Body)))
		case result.StatusCode < 500:
			operation.Stop().LogError(errors.New("client error"), zap.Int("statusCode", result.StatusCode), zap.String("responseBody", result.Body))
		default:
			operation.Stop().LogError(errors.New("server error"), zap.Int("statusCode", result.StatusCode), zap.String("responseBody", result.Body))
		}

		return result, nil // IMPORTANT: do not return any err, result handling manages that
	}
}

// MarshalResponse replaces nil maps + slices and serializes a response model.
//
// response is a pointer to a struct and statusCode is the http status to return
func MarshalResponse(response interface{}, statusCode int) *events.APIGatewayProxyResponse {
	ReplaceMapSliceNils(response)
	body, err := jsoniter.MarshalToString(response)
	if err != nil {
		zap.L().Error("failed to marshal response", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	return &events.APIGatewayProxyResponse{Body: body, StatusCode: statusCode}
}
