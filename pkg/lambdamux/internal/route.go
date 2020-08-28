package internal

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
	goerr "errors"
	"reflect"
	"regexp"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

type Handler interface {
	Invoke(ctx context.Context, payload []byte) ([]byte, error)
}

// CheckRouteName checks if a route name is valid
func CheckRouteName(name string) bool {
	return routeNameRegExp.MatchString(name)
}

var routeNameRegExp = regexp.MustCompile(`^[A-Z][A-Za-z0-9]+$`)

// Route is a named route method
type Route struct {
	name        string
	method      reflect.Value
	input       reflect.Type
	output      reflect.Type
	withContext bool
	withError   bool
}

// MustBuildRoute builds a route for a handler or panics
func MustBuildRoute(routeName string, handler interface{}) *Route {
	route, err := BuildRoute(routeName, handler)
	if err != nil {
		panic(err)
	}
	return route
}

// BuildRoute builds a route for a handler.
// If the handler does not meet the signature requirements it returns an error.
func BuildRoute(routeName string, handler interface{}) (*Route, error) {
	if !CheckRouteName(routeName) {
		return nil, errors.Errorf(`invalid route name %q`, routeName)
	}
	val := reflect.ValueOf(handler)
	route, err := buildRouteFromFunction(routeName, val)
	if err != nil {
		return nil, errors.Wrapf(err, `invalid %q handler %s`, routeName, val.Type())
	}
	return route, nil
}

// RouteMethods returns a route for each method of a struct that has the prefix.
func RouteMethods(prefix string, receiver interface{}) ([]*Route, error) {
	var routes []*Route
	val := reflect.ValueOf(receiver)
	typ := val.Type()
	switch typ.Kind() {
	case reflect.Ptr:
	case reflect.Interface:
	case reflect.Struct:
		return nil, errors.Errorf(`non-pointer receiver %s`, typ)
	default:
		return nil, errors.Errorf(`invalid receiver type %s`, typ)
	}
	if val.IsNil() {
		return nil, errors.Errorf(`nil receiver type %v`, val)
	}
	numMethod := typ.NumMethod()
	for i := 0; i < numMethod; i++ {
		method := typ.Method(i)
		if method.PkgPath != "" {
			// unexported method
			continue
		}
		if !strings.HasPrefix(method.Name, prefix) {
			continue
		}

		routeName := strings.TrimPrefix(method.Name, prefix)

		if !CheckRouteName(routeName) {
			return nil, errors.Errorf(`invalid route name %q`, routeName)
		}
		route, err := buildRouteFromMethod(routeName, val, method)
		if err != nil {
			return nil, errors.Wrapf(err, `invalid %q handler method %v`, routeName, method)
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// Name returns the route name
func (r *Route) Name() string {
	return r.name
}

// Input returns input argument type
func (r *Route) Input() reflect.Type {
	return r.input
}

// Output returns output argument type
func (r *Route) Output() reflect.Type {
	return r.output
}

// Handler builds a Handler for the route
func (r *Route) Handler(api jsoniter.API, validate func(interface{}) error) Handler {
	if validate == nil {
		validate = NopValidate
	}
	return &routeHandler{
		Route:    r,
		Validate: validate,
		JSON:     api,
	}
}

// NopValidate returns no errors.
// It is exported to avoid having to re-define it in generated client code
func NopValidate(_ interface{}) error {
	return nil
}

func (r *Route) setInputMethod(receiver reflect.Value, method reflect.Method) error {
	typ := method.Type
	switch typ.NumIn() {
	case 3:
		if r.setArgs2(typ.In(1), typ.In(2)) {
			return nil
		}
	case 2:
		if r.setArgs1(typ.In(1)) {
			return nil
		}
	}

	return errors.Errorf(`invalid method signature %q.%q %s`, receiver.Type(), method.Name, typ)
}

func (r *Route) setInputFunc(typ reflect.Type) error {
	switch typ.NumIn() {
	case 2:
		if r.setArgs2(typ.In(0), typ.In(1)) {
			return nil
		}
	case 1:
		if r.setArgs1(typ.In(0)) {
			return nil
		}
	}
	return errors.Errorf(`invalid function signature %s`, typ)
}

func (r *Route) setArgs1(arg reflect.Type) bool {
	if arg == typContext {
		r.withContext = true
		return true
	}
	if arg.Kind() != reflect.Ptr {
		return false
	}
	r.input = arg.Elem()
	return true
}

var (
	typContext = reflect.TypeOf((*context.Context)(nil)).Elem()
	typError   = reflect.TypeOf((*error)(nil)).Elem()
)

func (r *Route) setOutputs(typ reflect.Type) error {
	switch typ.NumOut() {
	case 0:
		return errors.New(`invalid signature (no return)`)
	case 1:
		out := typ.Out(0)
		if out == typError {
			r.withError = true
			return nil
		}
		if out.Kind() != reflect.Ptr {
			return errors.New(`invalid signature (return non pointer)`)
		}
		r.output = out.Elem()
		return nil
	case 2:
		typOut, typErr := typ.Out(0), typ.Out(1)
		if typErr != typError {
			return errors.New(`invalid signature (2nd return non error)`)
		}
		r.withError = true
		if typOut.Kind() != reflect.Ptr {
			return errors.New(`invalid signature (1st return non pointer)`)
		}
		r.output = typOut.Elem()
		return nil
	default:
		return errors.New(`invalid signature (return > 2)`)
	}
}

func (r *Route) setArgs2(arg0, arg1 reflect.Type) bool {
	if arg0 != typContext {
		return false
	}
	r.withContext = true
	if arg1.Kind() != reflect.Ptr {
		return false
	}
	r.input = arg1.Elem()
	return true
}

func buildRouteFromFunction(name string, val reflect.Value) (*Route, error) {
	typ := val.Type()
	if typ.Kind() != reflect.Func {
		return nil, errors.New(`invalid func value`)
	}
	route := Route{
		name: name,
	}
	if err := route.setInputFunc(typ); err != nil {
		return nil, err
	}
	if err := route.setOutputs(typ); err != nil {
		return nil, err
	}
	route.method = val
	return &route, nil
}

func buildRouteFromMethod(name string, receiver reflect.Value, method reflect.Method) (*Route, error) {
	route := Route{
		name: name,
	}
	if err := route.setInputMethod(receiver, method); err != nil {
		return nil, err
	}
	if err := route.setOutputs(method.Type); err != nil {
		return nil, err
	}
	route.method = receiver.Method(method.Index)
	return &route, nil
}

type routeHandler struct {
	*Route
	Validate func(interface{}) error
	JSON     jsoniter.API
}

var emptyResult = []byte(`{}`)

// Invoke implements Handler
func (r *routeHandler) Invoke(ctx context.Context, input []byte) ([]byte, error) {
	params, err := r.callParams(ctx, input)
	if err != nil {
		return nil, r.wrapErr(err)
	}
	result, err := r.call(params)
	if err != nil {
		return nil, r.wrapErr(err)
	}
	if result == nil {
		return emptyResult, nil
	}
	output, err := r.JSON.Marshal(result.Interface())
	if err != nil {
		return nil, r.wrapErr(err)
	}
	return output, nil
}

func (r *routeHandler) wrapErr(err error) error {
	if err != nil {
		return newRouteError(r.Name(), err)
	}
	return nil
}

func (r *routeHandler) callParams(ctx context.Context, input []byte) ([]reflect.Value, error) {
	in := make([]reflect.Value, 0, 2)
	if r.withContext {
		in = append(in, reflect.ValueOf(ctx))
	}
	if r.input != nil {
		inputVal := reflect.New(r.input)
		val := inputVal.Interface()
		if err := r.JSON.Unmarshal(input, val); err != nil {
			return nil, err
		}
		if err := r.Validate(val); err != nil {
			return nil, err
		}
		in = append(in, inputVal)
	}
	return in, nil
}

func (r *routeHandler) call(in []reflect.Value) (*reflect.Value, error) {
	switch out := r.method.Call(in); len(out) {
	case 2:
		outVal, errVal := &out[0], &out[1]
		if errVal.IsZero() || errVal.IsNil() {
			return outVal, nil
		}
		return nil, errVal.Interface().(error)
	case 1:
		outVal := &out[0]
		if r.withError {
			if outVal.IsNil() {
				return nil, nil
			}
			return nil, outVal.Interface().(error)
		}
		return outVal, nil
	default:
		return nil, goerr.New(`invalid route signature`)
	}
}

func newRouteError(route string, err error) error {
	return &routeError{
		routeName: route,
		err:       errors.WithMessagef(err, "route %q error", route),
	}
}

type RouteError interface {
	error
	Route() string
}
type routeError struct {
	routeName string
	err       error
}

func (e *routeError) Error() string {
	return e.err.Error()
}

func (e *routeError) Unwrap() error {
	return e.err
}

func (e *routeError) Route() string {
	return e.routeName
}
