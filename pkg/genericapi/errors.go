package genericapi

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import "github.com/aws/aws-lambda-go/lambda/messages"

// The Route in all the error messages is automatically set by the generic Router.

// AlreadyExistsError is raised if the item being created already exists.
type AlreadyExistsError struct {
	Route   string
	Message string
}

func (e *AlreadyExistsError) Error() string {
	return e.Message
}

// AWSError is raised if an AWS API call (e.g. to Dynamo/S3) failed.
type AWSError struct {
	Route  string
	Method string // name of the function that triggered the exception (e.g. "dynamodb.PutItem")
	Err    error  // error returned by the AWS SDK
}

func (e *AWSError) Error() string {
	return e.Err.Error()
}

// DoesNotExistError is raised if the item being retrieved or modified does not exist.
type DoesNotExistError struct {
	Route   string
	Message string
}

func (e *DoesNotExistError) Error() string {
	return e.Message
}

// InternalError is raised if there is an internal inconsistency in the code.
//
// For example, a failure marshaling a struct to JSON.
type InternalError struct {
	Route   string
	Message string
}

func (e *InternalError) Error() string {
	return e.Message
}

// InUseError is raised if the item cannot be modified or deleted because it's in use.
type InUseError struct {
	Route   string
	Message string
}

func (e *InUseError) Error() string {
	return e.Message
}

// InvalidInputError is raised if the request is invalid.
//
// For example, the request is missing an action or has invalid or missing fields.
// This is typically raised by the Validator, and indicates an error on the client side.
type InvalidInputError struct {
	Route   string
	Message string
}

func (e *InvalidInputError) Error() string {
	return e.Message
}

// LambdaError wraps the error structure returned by a Golang Lambda function.
//
// This applies to all errors - returned errors, panics, time outs, etc.
// This format is set by the AWS SDK: see messages.InvokeResponse_Error.
// (For some reason, the open-source Lambda SDK doesn't define a struct with the json tags that can
// be used to unmarshal the returned error.)
type LambdaError struct {
	// Route is the name of the API route if this error is ultimately returned by an API function.
	Route string

	// FunctionName is the qualified name of the function invoked (set by Invoke()).
	FunctionName string

	// ErrorMessage is always defined and contains the error string.
	ErrorMessage *string `json:"errorMessage"`

	// ErrorType is the name of the error class if applicable.
	// Some unhandled errors (e.g. task timed out) will not have an error type.
	// When panicking, the ErrorType is either "string" or the error type that caused the panic.
	ErrorType *string `json:"errorType"`

	// StackTrace is included only when the function panicked.
	StackTrace []*messages.InvokeResponse_Error_StackFrame `json:"stackTrace"`
}

func (e *LambdaError) Error() string {
	var result string

	if e.Route != "" {
		result = e.Route + " failed: "
	}

	result += "lambda error returned: "
	if e.FunctionName != "" {
		result += e.FunctionName + ": "
	}

	if e.ErrorMessage == nil {
		return result + "(nil)" // shouldn't happen, but just to prevent a potential panic
	}

	return result + *e.ErrorMessage
}
