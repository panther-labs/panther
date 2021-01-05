// Package genericapi provides a generic Router for API style Lambda functions.
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
	"context"
	"fmt"
	"reflect"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/pkg/oplog"
)

// Router is a generic API router for golang Lambda functions.
type Router struct {
	namespace    string
	component    string
	validate     *validator.Validate      // input validation
	routes       reflect.Value            // handler functions
	routesByName map[string]reflect.Value // cache routeName => handler function
}

// NewRouter initializes a Router with the handler functions and validator.
//
// validate is an optional custom validator
// routes is a struct pointer, whose receiver methods are handler functions (e.g. AddRule)
func NewRouter(namespace, component string, validate *validator.Validate, routes interface{}) *Router {
	if validate == nil {
		validate = validator.New()
	}
	reflected := reflect.ValueOf(routes)
	return &Router{
		namespace:    namespace,
		component:    component,
		validate:     validate,
		routes:       reflected,
		routesByName: make(map[string]reflect.Value, reflected.NumMethod()),
	}
}

// Handle validates the Lambda input and invokes the appropriate handler.
//
// For the sake of efficiency, no attempt is made to validate the routes or function signatures.
// As a result, this function will panic if a handler does not exist or is invalid.
// Be sure to VerifyHandlers as part of the unit tests for your function!
func (r *Router) Handle(input interface{}) (output interface{}, err error) {
	req, err := findRequest(input)
	if err != nil {
		// we do not have the route yet, special case, use oplog to keep logging standard
		operation := oplog.NewManager(r.namespace, r.component).Start("findRequest")
		operation.Stop()
		operation.Log(err)
		return nil, err
	}

	operation := oplog.NewManager(r.namespace, r.component).Start(req.route).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Any("input", redactedInput(req.input)))
	}()

	if err = r.validate.Struct(input); err != nil {
		var msg string
		if vErr, ok := err.(validator.ValidationErrors); ok {
			// The default error message looks like this:
			//     Key: 'Input.Name' Error:Field validation for 'Name' failed on the 'excludesall' tag
			// Restructure to be more user friendly:
			//     Name invalid, failed to satisfy the condition: excludesall=&<>
			fieldErr := []validator.FieldError(vErr)[0]
			property := fieldErr.Tag()
			if param := fieldErr.Param(); param != "" {
				// If the validation tag has parameters, include them in the message
				property += "=" + param
			}
			msg = fmt.Sprintf("%s invalid, failed to satisfy the condition: %s", fieldErr.Field(), property)
		} else {
			msg = err.Error()
		}

		return nil, &InvalidInputError{Route: req.route, Message: msg}
	}

	// Find the handler function, either cached or reflected.
	var handler reflect.Value
	var ok bool
	if handler, ok = r.routesByName[req.route]; !ok {
		// Cache miss - use reflection to find the function.
		handler = r.routes.MethodByName(req.route)
		r.routesByName[req.route] = handler
	}

	results := handler.Call([]reflect.Value{req.input})

	var payload interface{}
	switch len(results) {
	case 1:
		// single return: could be an error or the payload
		if results[0].IsNil() {
			return nil, nil
		}

		payload = results[0].Interface()
		if _, ok := payload.(error); ok {
			return nil, toError(results[0], req.route)
		}
	case 2:
		payload, err = results[0].Interface(), toError(results[1], req.route)
	default:
		panic(fmt.Sprintf("%s has %d returns, expected 1 or 2", req.route, len(results)))
	}

	if payload != nil {
		ReplaceMapSliceNils(&payload)
	}
	return payload, err
}

// Handle validates the Lambda input and invokes the appropriate handler with a context.
//
// For the sake of efficiency, no attempt is made to validate the routes or function signatures.
// As a result, this function will panic if a handler does not exist or is invalid.
// Be sure to VerifyHandlers as part of the unit tests for your function!
func (r *Router) HandleWithContext(ctx context.Context, input interface{}) (output interface{}, err error) {
	req, err := findRequest(input)
	if err != nil {
		// we do not have the route yet, special case, use oplog to keep logging standard
		operation := oplog.NewManager(r.namespace, r.component).Start("findRequest")
		operation.Stop()
		operation.Log(err)
		return nil, err
	}

	operation := oplog.NewManager(r.namespace, r.component).Start(req.route).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Any("input", redactedInput(req.input)))
	}()

	if err = r.validate.Struct(input); err != nil {
		var msg string
		if vErr, ok := err.(validator.ValidationErrors); ok {
			// The default error message looks like this:
			//     Key: 'Input.Name' Error:Field validation for 'Name' failed on the 'excludesall' tag
			// Restructure to be more user friendly:
			//     Name invalid, failed to satisfy the condition: excludesall=&<>
			fieldErr := []validator.FieldError(vErr)[0]
			property := fieldErr.Tag()
			if param := fieldErr.Param(); param != "" {
				// If the validation tag has parameters, include them in the message
				property += "=" + param
			}
			msg = fmt.Sprintf("%s invalid, failed to satisfy the condition: %s", fieldErr.Field(), property)
		} else {
			msg = err.Error()
		}

		return nil, &InvalidInputError{Route: req.route, Message: msg}
	}

	// Find the handler function, either cached or reflected.
	var handler reflect.Value
	var ok bool
	if handler, ok = r.routesByName[req.route]; !ok {
		// Cache miss - use reflection to find the function.
		handler = r.routes.MethodByName(req.route)
		r.routesByName[req.route] = handler
	}

	results := handler.Call([]reflect.Value{reflect.ValueOf(ctx), req.input})

	var payload interface{}
	switch len(results) {
	case 1:
		// single return: could be an error or the payload
		if results[0].IsNil() {
			return nil, nil
		}

		payload = results[0].Interface()
		if _, ok := payload.(error); ok {
			return nil, toError(results[0], req.route)
		}
	case 2:
		payload, err = results[0].Interface(), toError(results[1], req.route)
	default:
		panic(fmt.Sprintf("%s has %d returns, expected 1 or 2", req.route, len(results)))
	}

	if payload != nil {
		ReplaceMapSliceNils(&payload)
	}
	return payload, err
}

type request struct {
	route string        // name of the route, e.g. "AddRule"
	input reflect.Value // input for the route handler, e.g. &AddRuleInput{}
}

// findRequest searches the Lambda invocation struct for the route name and associated input.
//
// Returns an error unless there is exactly one non-nil entry.
func findRequest(lambdaInput interface{}) (*request, error) {
	// lambdaInput is a struct pointer, e.g. &{AddRule: *AddRuleInput, DeleteRule: *DeleteRuleInput}
	// Follow the pointer to get the reflect.Value of the underlying input struct.
	structValue := reflect.Indirect(reflect.ValueOf(lambdaInput))

	// Check the name and value of each field in the input struct - only one should be non-nil.
	requests := findNonNullPtrs(structValue)
	switch len(requests) {
	case 1:
		return &requests[0], nil
	case 0:
		return nil, &InvalidInputError{
			Route: "nil", Message: "exactly one route must be specified: found none",
		}
	default:
		// There is more than one route
		var routes []string
		for _, request := range requests {
			routes = append(routes, request.route)
		}
		return nil, &InvalidInputError{
			Route:   "",
			Message: fmt.Sprintf("exactly one route must be specified: %v", routes),
		}
	}
}

func findNonNullPtrs(structValue reflect.Value) (requests []request) {
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)

		// embedded structs are used for API composition
		if fieldValue.Type().Kind() == reflect.Struct {
			requests = append(requests, findNonNullPtrs(fieldValue)...)
			continue
		}

		if fieldValue.IsNil() {
			continue
		}

		fieldName := structValue.Type().Field(i).Name
		requests = append(requests, request{route: fieldName, input: fieldValue})
	}

	return requests
}

// Convert a return value into an error, injecting the route name if applicable.
func toError(val reflect.Value, routeName string) error {
	if val.IsNil() {
		return nil
	}

	// error is an interface, look for a field in the underlying struct
	field := reflect.Indirect(val.Elem()).FieldByName("Route")
	if field.IsValid() {
		field.SetString(routeName)
	}
	return val.Interface().(error)
}
