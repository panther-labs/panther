// Package genericapi provides a generic Router for API style Lambda functions.
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
	"reflect"

	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/pkg/gatewayapi"
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

	operation := oplog.NewManager(r.namespace, r.component).Start(req.route)
	defer func() {
		operation.Stop()
		operation.Log(err, zap.Any("input", redactedInput(req.input)))
	}()

	if err = r.validate.Struct(input); err != nil {
		return nil, &InvalidInputError{Route: req.route, Message: err.Error()}
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

	if len(results) == 1 {
		return nil, toError(results[0], req.route)
	}

	result, err := results[0].Interface(), toError(results[1], req.route)
	if result != nil {
		gatewayapi.ReplaceMapSliceNils(&result)
	}
	return result, err
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
	var result *request
	for i := 0; i < structValue.NumField(); i++ {
		fieldValue := structValue.Field(i)
		if fieldValue.IsNil() {
			continue
		}

		fieldName := structValue.Type().Field(i).Name
		if result == nil {
			// We found the first defined route
			result = &request{route: fieldName, input: fieldValue}
		} else {
			// There is more than one route
			return nil, &InvalidInputError{
				Route:   result.route,
				Message: "exactly one route must be specified: also found " + fieldName,
			}
		}
	}

	if result == nil {
		return nil, &InvalidInputError{
			Route: "nil", Message: "exactly one route must be specified: found none"}
	}
	return result, nil
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
