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
	goerr "errors"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

type Mux struct {
	// JSON can be used to specialize the configuration and extensions used by jsoniter
	JSON jsoniter.API
	// Decorate can be used to decorate the route handlers when building the mux handler
	Decorate func(routeName string, handler Handler) Handler
	// NotFound is the fallback handler if a route is not found.
	NotFound Handler
	Validate func(interface{}) error
	handlers map[string]Handler
}

func (m *Mux) Routes() (routes []*Route) {
	for _, handler := range m.handlers {
		if r, ok := handler.(*routeHandler); ok {
			routes = append(routes, r.Route)
		}
	}
	return
}

func (m *Mux) HandleRoutes(routes ...*Route) {
	for _, route := range routes {
		name := route.Name()
		handler := route.Handler(m.JSON, m.Validate)
		m.Handle(name, handler)
	}
}

func (m *Mux) Handle(routeName string, handler Handler) {
	if decorate := m.Decorate; decorate != nil {
		handler = decorate(routeName, handler)
	}
	if handler == nil {
		return
	}
	if m.handlers == nil {
		m.handlers = make(map[string]Handler)
	}
	m.handlers[routeName] = handler
}

func (m *Mux) MustHandleStructs(methodPrefix string, structHandlers ...interface{}) {
	if err := m.HandleStructs(methodPrefix, structHandlers...); err != nil {
		panic(err)
	}
}

func (m *Mux) HandleStructs(methodPrefix string, structHandlers ...interface{}) error {
	for _, s := range structHandlers {
		routes, err := StructRoutes(methodPrefix, s)
		if err != nil {
			return err
		}
		m.HandleRoutes(routes...)
	}
	return nil
}

func (m *Mux) HandleRaw(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	jsonAPI := resolveJSON(m.JSON)
	iter := jsonAPI.BorrowIterator(input)
	defer jsonAPI.ReturnIterator(iter)
	routeName := iter.ReadObject()
	payload := iter.SkipAndReturnBytes()
	if handler, ok := m.handlers[routeName]; ok {
		reply, err := handler.HandleRaw(ctx, payload)
		if err != nil {
			return nil, NewRouteError(routeName, err)
		}
		return reply, nil
	}
	if notFound := m.NotFound; notFound != nil {
		return notFound.HandleRaw(ctx, input)
	}
	return nil, NewRouteError(routeName, errors.WithStack(ErrRouteNotFound))
}

const DefaultHandlerPrefix = "Handle"

// ErrRouteNotFound is a well-known error that a route was not found.
// Using std errors.New here since we don't want a stack
var ErrRouteNotFound = goerr.New(`route not found`)

func NewRouteError(route string, err error) error {
	return &RouteError{
		routeName: route,
		err:       err,
	}
}

type RouteError struct {
	routeName string
	err       error
}

func (e *RouteError) Error() string {
	return fmt.Sprintf(`route %q error: %s`, e.routeName, e.err)
}

func (e *RouteError) Unwrap() error {
	return e.err
}

func (e *RouteError) Route() string {
	return e.routeName
}
