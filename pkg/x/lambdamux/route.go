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
	"fmt"
	"reflect"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

// Route is a named route method
type routeHandler struct {
	name        string
	method      reflect.Value
	input       reflect.Type
	output      reflect.Type
	withContext bool
	withError   bool
	validate    func(interface{}) error
	jsonAPI     jsoniter.API
}

// MustBuildRoute builds a route for a handler or panics
func mustBuildRoute(routeName string, handler interface{}) *routeHandler {
	route, err := buildRoute(routeName, handler)
	if err != nil {
		panic(err)
	}
	return route
}

// BuildRoute builds a route for a handler.
// If the handler does not meet the signature requirements it returns an error.
func buildRoute(routeName string, handler interface{}) (*routeHandler, error) {
	val := reflect.ValueOf(handler)
	route, err := buildRouteHandler(routeName, val)
	if err != nil {
		return nil, errors.WithMessagef(err, `invalid %q handler %s`, routeName, val.Type())
	}
	return route, nil
}

func routeMethods(prefix string, receiver interface{}) ([]*routeHandler, error) {
	var routes []*routeHandler
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
		return nil, errors.Errorf(`nil receiver %v`, val)
	}
	numMethod := typ.NumMethod()
	for i := 0; i < numMethod; i++ {
		method := typ.Method(i)
		if method.PkgPath != "" {
			// unexported method
			continue
		}

		routeName := method.Name
		if prefix != "" {
			if !strings.HasPrefix(routeName, prefix) {
				continue
			}
			routeName = strings.TrimPrefix(routeName, prefix)
		}

		route, err := buildRouteHandler(routeName, val.Method(i))
		if err != nil {
			return nil, errors.WithMessagef(err, `invalid %q handler method`, method.Name)
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func buildRouteHandler(name string, method reflect.Value) (*routeHandler, error) {
	typ := method.Type()
	if typ.Kind() != reflect.Func {
		return nil, errors.New(`invalid func value`)
	}
	route := routeHandler{
		name:     name,
		method:   method,
		jsonAPI:  defaultJSON,
		validate: nopValidate,
	}
	if err := route.setInput(typ); err != nil {
		return nil, errors.WithMessagef(err, "invalid signature input %s", typ)
	}
	if err := route.setOutput(typ); err != nil {
		return nil, errors.WithMessagef(err, "invalid signature output %s", typ)
	}
	return &route, nil
}

func (r *routeHandler) setInput(typ reflect.Type) error {
	switch typ.NumIn() {
	case 2:
		ctx, in := typ.In(0), typ.In(1)
		if ctx != typContext {
			return errors.New("first input is not context.Context")
		}
		r.withContext = true
		if in.Kind() != reflect.Ptr {
			return errors.New("second input is not a pointer")
		}
		r.input = in.Elem()
		return nil
	case 1:
		in := typ.In(0)
		if in == typContext {
			r.withContext = true
			return nil
		}
		if in.Kind() != reflect.Ptr {
			return errors.New("input is not a pointer")
		}
		r.input = in.Elem()
		return nil
	case 0:
		return nil
	}
	return errors.Errorf(`invalid signature input %s`, typ)
}

var (
	typContext = reflect.TypeOf((*context.Context)(nil)).Elem()
	typError   = reflect.TypeOf((*error)(nil)).Elem()
)

func (r *routeHandler) setOutput(typ reflect.Type) error {
	switch typ.NumOut() {
	case 0:
		return errors.New(`no output`)
	case 1:
		out := typ.Out(0)
		if out == typError {
			r.withError = true
			return nil
		}
		if out.Kind() != reflect.Ptr {
			return errors.New(`output type non pointer`)
		}
		r.output = out.Elem()
		return nil
	case 2:
		typOut, typErr := typ.Out(0), typ.Out(1)
		if typErr != typError {
			return errors.New(`second output is not error`)
		}
		r.withError = true
		if typOut.Kind() != reflect.Ptr {
			return errors.New(`first output is not a pointer`)
		}
		r.output = typOut.Elem()
		return nil
	default:
		return errors.New(`too many outputs`)
	}
}

func (r *routeHandler) Route() string {
	return r.name
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
	output, err := r.jsonAPI.Marshal(result.Interface())
	if err != nil {
		return nil, r.wrapErr(errors.Wrap(err, "failed to marshal reply"))
	}
	return output, nil
}

func (r *routeHandler) wrapErr(err error) error {
	if err != nil {
		return newRouteError(r.Route(), err)
	}
	return nil
}

func (r *routeHandler) callParams(ctx context.Context, payload []byte) ([]reflect.Value, error) {
	in := make([]reflect.Value, 0, 2)
	if r.withContext {
		in = append(in, reflect.ValueOf(ctx))
	}
	if r.input != nil {
		inputVal := reflect.New(r.input)
		val := inputVal.Interface()
		if err := r.jsonAPI.Unmarshal(payload, val); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal payload")
		}
		if err := r.validate(val); err != nil {
			return nil, errors.WithMessage(err, "invalid payload")
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
		return nil, errors.New(`invalid route signature`)
	}
}

func newRouteError(route string, err error) error {
	if e, ok := err.(*routeError); ok {
		err = e.err
	}
	return &routeError{
		routeName: route,
		err:       err,
	}
}

type routeError struct {
	routeName string
	err       error
}

var _ RouteError = (*routeError)(nil)

func (e *routeError) Error() string {
	return fmt.Sprintf("route %q error: %s", e.routeName, e.err)
}

func (e *routeError) Unwrap() error {
	return e.err
}

func (e *routeError) Route() string {
	return e.routeName
}

func nopValidate(_ interface{}) error {
	return nil
}
