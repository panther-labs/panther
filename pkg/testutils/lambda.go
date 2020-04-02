package testutils

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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
)

func InvokeLambda(awsSession *session.Session, functionName string, input interface{}, output interface{}) error {
	payload, err := jsoniter.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to json marshal input to %s: %v", functionName, err)
	}

	response, err := lambda.New(awsSession).Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(functionName),
		Payload:      payload,
	})
	if err != nil {
		return fmt.Errorf("%s lambda invocation failed: %v", functionName, err)
	}

	if response.FunctionError != nil {
		return fmt.Errorf("%s responded with %s error: %s",
			functionName, *response.FunctionError, string(response.Payload))
	}

	if output != nil {
		if err = jsoniter.Unmarshal(response.Payload, output); err != nil {
			return fmt.Errorf("failed to json unmarshal response from %s: %v", functionName, err)
		}
	}
	return nil
}
