package genericapi

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
		// could be an error or the response payload
		return nil
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
