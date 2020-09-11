package gatewayapi

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

		operation := oplog.NewManager("api", lc.InvokedFunctionArn).Start(methodKey).WithMemUsed(lambdacontext.MemoryLimitInMB)

		handler, ok := methodHandlers[methodKey]
		if !ok {
			operation.Stop().LogWarn(errors.New("unexpected method/resource"))
			// IMPORTANT: do not return any err, result handling manages that
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotImplemented}, nil
		}

		result = handler(input)

		switch {
		case result.StatusCode < 400:
			operation.Stop().LogSuccess(zap.Int("statusCode", result.StatusCode), zap.Int("bodyLength", len(result.Body)))
		case result.StatusCode < 500:
			operation.Stop().LogNonCriticalError(
				errors.New("client error"), zap.Int("statusCode", result.StatusCode), zap.String("responseBody", result.Body))
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
