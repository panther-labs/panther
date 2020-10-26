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
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

type API interface {
	Invoke(input, output interface{}) (int, error)
}

type Client struct {
	lambda       lambdaiface.LambdaAPI
	functionName string
}

// Create a new client for invoking a lambda gateway API proxy directly.
func NewClient(lambda lambdaiface.LambdaAPI, functionName string) *Client {
	return &Client{lambda: lambda, functionName: functionName}
}

// Error returned by genericapi for failed input validation
type genericError struct {
	ErrorMessage string `json:"errorMessage"`
	ErrorType    string `json:"errorType"`
}

// Invoke a former API gateway proxy Lambda directly.
//
// Unmarshals the response body into output and returns (http status code, error).
// A non-nil error could be caused by:
//     - failure to marshal request / unmarshal response
//     - lambda function failed to invoke (does not exist, insufficient permissions)
//     - lambda function runtime exception (panic, OOM, timeout)
//     - status code is not 2XX
//
// This is similar to genericapi.Invoke and will be obsolete once we consolidate the internal API.
func (client *Client) Invoke(input, output interface{}) (int, error) {
	payload, err := jsoniter.Marshal(input)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("%s: jsoniter.Marshal(input) failed: %s", client.functionName, err)
	}

	zap.L().Debug(
		"invoking gateway Lambda function",
		zap.String("name", client.functionName), zap.Int("bytes", len(payload)))
	response, err := client.lambda.Invoke(
		&lambda.InvokeInput{FunctionName: &client.functionName, Payload: payload})

	// Invocation failed - permission error, function doesn't exist, etc
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("%s: lambda.Invoke() failed: %s", client.functionName, err)
	}

	// The Lambda function returned an error.
	if response.FunctionError != nil {
		// This could be an input validation error
		var result genericError
		if err := jsoniter.Unmarshal(response.Payload, &result); err == nil && result.ErrorType == "InvalidInputError" {
			return http.StatusBadRequest, fmt.Errorf("%s: InvalidInputError: %s", client.functionName, result.ErrorMessage)
		}

		// unknown error payload, probably a panic or other runtime exception
		return http.StatusInternalServerError, fmt.Errorf("%s: execution failed: %s", client.functionName, response.Payload)
	}

	// All gateway proxies had to return this type for API gateway.
	var result events.APIGatewayProxyResponse
	if err := jsoniter.Unmarshal(response.Payload, &result); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("%s: proxy response could not be parsed: %s", client.functionName, response)
	}

	if result.StatusCode < 200 || result.StatusCode >= 300 {
		return result.StatusCode, fmt.Errorf("%s: unsuccessful status code %d: %s",
			client.functionName, result.StatusCode, result.Body)
	}

	if output != nil {
		if err := jsoniter.UnmarshalFromString(result.Body, output); err != nil {
			return http.StatusInternalServerError, fmt.Errorf("%s: response could not be parsed into output variable: %s",
				client.functionName, err)
		}
	}

	return result.StatusCode, nil
}
