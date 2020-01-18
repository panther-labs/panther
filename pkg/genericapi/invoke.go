package genericapi

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
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

// Invoke a Lambda function, taking care of error checking and json marshaling.
//
// Arguments:
//     - client: initialized Lambda client
//     - function: function name (optionally qualified), e.g. "panther-rules-api"
//     - input: (pointer to struct) payload for Lambda function, processed via jsoniter.Marshal()
//     - output: (optional - pointer to struct) Lambda response is jsoniter.Unmarshal()ed here
//         - If nil, the Lambda response is ignored
//
// Use a type assertion on the returned error to distinguish different error conditions:
//     - AWSError: lambda invocation failed (e.g. permission error)
//     - InternalError: json marshal/unmarshal failed
//     - LambdaError: lambda function returned an error, directly or indirectly (timeout, panic, etc)
//
// Example:
//
// client := lambda.New(session.Must(session.NewSession()))
// input := models.LambdaInput{AddRule: ...}
// var output models.AddRuleOutput
// err := Invoke(client, "panther-rules-api", &input, &output)
func Invoke(
	client lambdaiface.LambdaAPI, function string, input interface{}, output interface{}) error {

	payload, err := jsoniter.Marshal(input)
	if err != nil {
		return &InternalError{Message: "jsoniter.Marshal(input) failed: " + err.Error()}
	}

	zap.L().Info(
		"invoking Lambda function", zap.String("name", function), zap.Int("bytes", len(payload)))
	response, err := client.Invoke(
		&lambda.InvokeInput{FunctionName: aws.String(function), Payload: payload})

	// Invocation failed - permission error, function doesn't exist, etc
	if err != nil {
		return &AWSError{Method: "lambda.Invoke", Err: err}
	}

	// Function returned an error, directly or indirectly (e.g. InvalidInputError, out of memory)
	if response.FunctionError != nil {
		errLambda := &LambdaError{FunctionName: function}
		if err = jsoniter.Unmarshal(response.Payload, errLambda); err != nil {
			return &InternalError{Message: fmt.Sprintf(
				"%s invocation failed (%s) and the response could not be parsed: %s",
				function,
				string(response.Payload),
				err.Error(),
			)}
		}
		return errLambda
	}

	if output != nil {
		if err := jsoniter.Unmarshal(response.Payload, output); err != nil {
			return &InternalError{
				Message: "jsoniter.Unmarshal(response.Payload) failed: " + err.Error()}
		}
	}

	return nil
}
