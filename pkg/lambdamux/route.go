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
	"encoding/json"
	"reflect"
	"regexp"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

func CheckRouteName(name string) bool {
	return routeNameRegExp.MatchString(name)
}

var routeNameRegExp = regexp.MustCompile(`^[A-Z][A-Za-z0-9]+$`)

type Route struct {
	name        string
	method      reflect.Value
	input       reflect.Type
	output      reflect.Type
	withContext bool
	withError   bool
}

func MustBuildRoute(routeName string, handler interface{}) *Route {
	route, err := BuildRoute(routeName, handler)
	if err != nil {
		panic(err)
	}
	return route
}

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

func AppendStructRoutes(routes []*Route, methodPrefix string, structHandler interface{}) ([]*Route, error) {
	structRoutes, err := StructRoutes(methodPrefix, structHandler)
	if err != nil {
		return routes, nil
	}
	return append(routes, structRoutes...), nil
}

func StructRoutes(methodPrefix string, structHandler interface{}) ([]*Route, error) {
	var routes []*Route
	val := reflect.ValueOf(structHandler)
	typ := val.Type()
	numMethod := typ.NumMethod()
	for i := 0; i < numMethod; i++ {
		method := typ.Method(i)
		if method.PkgPath != "" {
			// unexported method
			continue
		}
		if !strings.HasPrefix(method.Name, methodPrefix) {
			continue
		}

		routeName := strings.TrimPrefix(method.Name, methodPrefix)

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

func (r *Route) Name() string {
	return r.name
}
func (r *Route) Input() reflect.Type {
	return r.input
}
func (r *Route) Output() reflect.Type {
	return r.output
}

func (r *Route) Handler(api jsoniter.API, validate func(interface{}) error) Handler {
	return &routeHandler{
		Route:    r,
		Validate: validate,
		JSON:     resolveJSON(api),
	}
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

var emptyResult = json.RawMessage(`{}`)

func (r *routeHandler) HandleRaw(ctx context.Context, input json.RawMessage) (output json.RawMessage, err error) {
	out, err := r.HandleJSON(ctx, input)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return emptyResult, nil
	}
	return r.JSON.Marshal(out)
}

func (r *routeHandler) HandleJSON(ctx context.Context, input json.RawMessage) (interface{}, error) {
	in := make([]reflect.Value, 0, 3)
	if r.withContext {
		in = append(in, reflect.ValueOf(ctx))
	}
	if r.input != nil {
		val := reflect.New(r.input)
		x := val.Interface()
		if err := r.JSON.Unmarshal(input, x); err != nil {
			return nil, err
		}
		if r.Validate != nil {
			if err := r.Validate(x); err != nil {
				return nil, err
			}
		}
		in = append(in, val)
	}
	switch out := r.method.Call(in); len(out) {
	case 2:
		outVal, errVal := out[0], out[1]
		if errVal.IsZero() || errVal.IsNil() {
			return outVal.Interface(), nil
		}
		return nil, errVal.Interface().(error)
	case 1:
		outVal := out[0]
		if r.withError {
			if outVal.IsNil() {
				return nil, nil
			}
			return nil, outVal.Interface().(error)
		}
		return outVal.Interface(), nil
	default:
		return nil, errors.New(`invalid route signature`)
	}
}

var defaultJSON = jsoniter.ConfigDefault

func resolveJSON(api jsoniter.API) jsoniter.API {
	if api != nil {
		return api
	}
	return defaultJSON
}
