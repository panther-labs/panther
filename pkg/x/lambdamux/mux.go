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

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

// Mux dispatches handling of a Lambda events
type Mux struct {
	// If set, it will normalize route names.
	RouteName func(name string) string
	// Decorate can intercept new handlers and add decorations
	Decorate func(key string, handler Handler) Handler
	// JSON
	JSON jsoniter.API // defaults to jsoniter.ConfigCompatibleWithStandardLibrary
	// Validate sets a custom validation function to be injected into every route handler
	Validate func(payload interface{}) error
	// IgnoreDuplicates will not return errors when duplicate route handlers are added to the mux
	IgnoreDuplicates bool

	handlers map[string]RouteHandler
}

// Handlers returns all handlers added to the mux.
func (m *Mux) Handlers() (handlers []RouteHandler) {
	if len(m.handlers) == 0 {
		return
	}
	handlers = make([]RouteHandler, 0, len(m.handlers))
	for _, handler := range m.handlers {
		handlers = append(handlers, handler)
	}
	return
}

// MustHandleMethods add all routes from a struct to the Mux or panics.
// It overrides previously defined routes without error if IgnoreDuplicates is set
func (m *Mux) MustHandleMethods(receivers ...interface{}) {
	if err := m.HandleMethodsPrefix("", receivers...); err != nil {
		panic(err)
	}
}

// HandleMethodsPrefix add all routes from a struct to the Mux.
// It fails if a method does not meet the signature requirements.
// It overrides previously defined routes without error if IgnoreDuplicates is set
func (m *Mux) HandleMethodsPrefix(prefix string, receivers ...interface{}) error {
	for _, receiver := range receivers {
		routes, err := routeMethods(prefix, receiver)
		if err != nil {
			return err
		}
		if err := m.handleRoutes(routes...); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mux) handleRoutes(routes ...*routeHandler) error {
	for _, route := range routes {
		name := route.name
		if err := m.Handle(name, route); err != nil {
			return err
		}
	}
	return nil
}
func (m *Mux) MustHandle(name string, handler interface{}) {
	if err := m.Handle(name, handler); err != nil {
		panic(err)
	}
}

// Handle applies any decoration and adds a handler to the mux.
// It fails if the handler does not meet the signature requirements.
// It overrides previously defined routes without error if IgnoreDuplicates is set.
func (m *Mux) Handle(name string, handler interface{}) error {
	key := name
	if m.RouteName != nil {
		key = m.RouteName(name)
	}
	if key == "" {
		return errors.Errorf("invalid route name %q", name)
	}

	var route RouteHandler
	switch h := handler.(type) {
	case *routeHandler:
		r := *h
		r.name = key
		if m.JSON != nil {
			r.jsonAPI = m.JSON
		}
		if m.Validate != nil {
			r.validate = m.Validate
		}
		route = &r
	case Handler:
		route = &namedHandler{
			Handler: h,
			route:   key,
		}
	default:
		r, err := buildRoute(key, handler)
		if err != nil {
			return err
		}
		if m.JSON != nil {
			r.jsonAPI = m.JSON
		}
		if m.Validate != nil {
			r.validate = m.Validate
		}
		route = r
	}

	if decorate := m.Decorate; decorate != nil {
		d := decorate(key, route)
		// Allow Decorate to filter routes
		if d == nil {
			return nil
		}
		route = &namedHandler{
			Handler: d,
			route:   key,
		}
	}

	if !m.IgnoreDuplicates {
		if _, duplicate := m.handlers[key]; duplicate {
			return errors.Errorf("duplicate route handler for %q", name)
		}
	}

	if m.handlers == nil {
		m.handlers = map[string]RouteHandler{}
	}
	m.handlers[key] = route
	return nil
}

func (m *Mux) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	iter := resolveJSON(m.JSON).BorrowIterator(payload)
	defer iter.Pool().ReturnIterator(iter)
	for name := iter.ReadObject(); name != ""; name = iter.ReadObject() {
		if iter.WhatIsNext() == jsoniter.NilValue {
			iter.Skip()
			continue
		}
		handler, err := m.Get(name)
		if err != nil {
			return nil, err
		}
		payload := iter.SkipAndReturnBytes()
		return handler.Invoke(ctx, payload)
	}
	return nil, errors.New("empty payload")
}

func (m *Mux) Get(name string) (Handler, error) {
	if name == "" {
		return nil, errors.Wrap(ErrNotFound, `invalid payload`)
	}
	key := name
	if m.RouteName != nil {
		key = m.RouteName(key)
		if key == "" {
			return nil, errors.Wrapf(ErrNotFound, `invalid route key %q`, name)
		}
	}
	if handler, ok := m.handlers[key]; ok {
		return handler, nil
	}
	return nil, errors.Wrapf(ErrNotFound, "route %q not found", key)
}

type namedHandler struct {
	Handler
	route string
}

var _ RouteHandler = (*namedHandler)(nil)

func (h *namedHandler) Route() string {
	return h.route
}

func (h *namedHandler) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	reply, err := h.Handler.Invoke(ctx, payload)
	if err != nil {
		return nil, newRouteError(h.route, err)
	}
	return reply, nil
}
