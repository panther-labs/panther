package lambdamux

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
	"github.com/pkg/errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
)

type InvokeError struct {
	Message    string            `json:"errorMessage"`
	Type       string            `json:"errorType"`
	StackTrace []ErrorStackFrame `json:"stackTrace,omitempty"`
}

func (e *InvokeError) Error() string {
	return e.Message
}

type ErrorStackFrame struct {
	Path  string `json:"path"`
	Line  int32  `json:"line"`
	Label string `json:"label"`
}

type Client struct {
	LambdaAPI  lambdaiface.LambdaAPI
	LambdaName string
	JSON       jsoniter.API
	Validate   func(interface{}) error
}

func (c *Client) InvokeWithContext(ctx context.Context, input, output interface{}) error {
	jsonAPI := c.JSON
	if jsonAPI == nil {
		jsonAPI = jsoniter.ConfigDefault
	}
	payload, err := jsonAPI.Marshal(input)
	if err != nil {
		return errors.Wrapf(err, `failed to marshal lambda %q input`, c.LambdaName)
	}
	lambdaInput := lambda.InvokeInput{
		FunctionName: aws.String(c.LambdaName),
		Payload:      payload,
	}
	lambdaOutput, err := c.LambdaAPI.InvokeWithContext(ctx, &lambdaInput)
	if err != nil {
		return errors.Wrapf(err, `lambda %q invocation failed`, c.LambdaName)
	}
	if lambdaOutput.FunctionError != nil {
		invokeErr := InvokeError{}
		if err := jsoniter.Unmarshal(lambdaOutput.Payload, &invokeErr); err != nil {
			return errors.Wrapf(err, `failed to unmarshal lambda %q invoke error`, c.LambdaName)
		}
		return errors.Wrapf(&invokeErr, `lambda %q execution failed`, c.LambdaName)
	}
	if output == nil {
		return nil
	}
	if err := jsonAPI.Unmarshal(lambdaOutput.Payload, output); err != nil {
		return errors.Wrapf(err, `failed to marshal lambda %q response`, c.LambdaName)
	}
	return nil
}
