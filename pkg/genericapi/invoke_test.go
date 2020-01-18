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
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const functionName = "myfunc"

type mockLambdaClient struct {
	lambdaiface.LambdaAPI
	serviceError         bool
	functionError        bool
	functionInvalidError bool
}

func (m *mockLambdaClient) Invoke(*lambda.InvokeInput) (*lambda.InvokeOutput, error) {
	if m.serviceError {
		return nil, errors.New("function does not exist")
	}

	if m.functionError {
		return &lambda.InvokeOutput{
			FunctionError: aws.String("Unhandled"),
			Payload:       []byte(`{"errorMessage": "task timed out"}`),
		}, nil
	}

	if m.functionInvalidError {
		return &lambda.InvokeOutput{
			FunctionError: aws.String("Unhandled"),
			Payload:       []byte(`{"not json`),
		}, nil
	}

	return &lambda.InvokeOutput{Payload: []byte(`{"name": "panther", "size": 5}`)}, nil
}

func TestInvokeMarshalError(t *testing.T) {
	err := Invoke(&mockLambdaClient{}, functionName, Invoke, nil)
	assert.Error(t, err)
}

func TestInvokeServiceError(t *testing.T) {
	err := Invoke(&mockLambdaClient{serviceError: true}, functionName, nil, nil)
	require.Error(t, err)
	assert.IsType(t, &AWSError{}, err)
}

func TestInvokeFunctionError(t *testing.T) {
	err := Invoke(&mockLambdaClient{functionError: true}, functionName, nil, nil)
	require.Error(t, err)
	assert.Equal(t, "task timed out", *err.(*LambdaError).ErrorMessage)
}

func TestInvokeFunctionInvalidError(t *testing.T) {
	err := Invoke(&mockLambdaClient{functionInvalidError: true}, functionName, nil, nil)
	assert.True(t, strings.HasPrefix(err.(*InternalError).Message, "myfunc invocation failed"))
}

func TestInvokeIgnoreOutput(t *testing.T) {
	assert.NoError(t, Invoke(&mockLambdaClient{}, functionName, nil, nil))
}

func TestInvokeUnmarshalError(t *testing.T) {
	type testoutput struct{ Name []string }
	var output testoutput
	assert.Error(t, Invoke(&mockLambdaClient{}, functionName, nil, &output))
}

func TestInvoke(t *testing.T) {
	type testinput struct{ Name string }
	type testoutput struct {
		Name string
		Size int
	}

	var output testoutput
	require.NoError(t, Invoke(&mockLambdaClient{}, functionName, &testinput{}, &output))
	assert.Equal(t, testoutput{Name: "panther", Size: 5}, output)
}
