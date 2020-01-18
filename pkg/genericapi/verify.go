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
	"reflect"
)

// VerifyHandlers returns an error if the route handlers don't match the Lambda input struct.
//
// This should be part of the unit tests for your Lambda function.
func (r *Router) VerifyHandlers(lambdaInput interface{}) error {
	inputValue := reflect.Indirect(reflect.ValueOf(lambdaInput))
	numFields := inputValue.NumField()

	if numFields != r.routes.NumMethod() {
		return &InternalError{Message: fmt.Sprintf(
			"input has %d fields but there are %d handlers", numFields, r.routes.NumMethod())}
	}

	// Loop over the fields in the lambda input struct
	inputType := inputValue.Type()
	for i := 0; i < numFields; i++ {
		handlerName := inputType.Field(i).Name
		handler := r.routes.MethodByName(handlerName)
		if !handler.IsValid() {
			return &InternalError{Message: "func " + handlerName + " does not exist"}
		}

		err := verifySignature(handlerName, handler.Type(), inputValue.Field(i).Type())
		if err != nil {
			return err
		}
	}

	return nil
}

// verifySignature returns an error if the handler function signature is invalid.
func verifySignature(name string, handler reflect.Type, input reflect.Type) error {
	if handler.NumIn() != 1 {
		return &InternalError{Message: fmt.Sprintf(
			"%s should have 1 argument, found %d", name, handler.NumIn())}
	}

	if handler.In(0) != input {
		return &InternalError{Message: fmt.Sprintf(
			"%s expects an argument of type %s, input has type %s",
			name, handler.In(0).String(), input.String())}
	}

	errorInterface := reflect.TypeOf((*error)(nil)).Elem()

	switch handler.NumOut() {
	case 1:
		if !handler.Out(0).Implements(errorInterface) {
			return &InternalError{Message: fmt.Sprintf(
				"%s returns %s, which does not satisfy error", name, handler.Out(0).String())}
		}
	case 2:
		if !handler.Out(1).Implements(errorInterface) {
			return &InternalError{Message: fmt.Sprintf(
				"%s second return is %s, which does not satisfy error",
				name, handler.Out(1).String())}
		}
	default:
		return &InternalError{Message: fmt.Sprintf(
			"%s should have 1 or 2 returns, found %d", name, handler.NumOut())}
	}

	return nil
}
