package lambdamux

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"context"
	"encoding/json"
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
	handlers map[string]Handler
}

func (b *Mux) Routes() (routes []*Route) {
	for _, handler := range b.handlers {
		if r, ok := handler.(*routeHandler); ok {
			routes = append(routes, r.Route)
		}
	}
	return
}

func (b *Mux) HandleRoutes(routes ...*Route) {
	for _, route := range routes {
		name := route.Name()
		handler := route.Handler(b.JSON)
		b.Handle(name, handler)
	}
}

func (b *Mux) Handle(routeName string, handler Handler) {
	if decorate := b.Decorate; decorate != nil {
		handler = decorate(routeName, handler)
	}
	if handler == nil {
		return
	}
	if b.handlers == nil {
		b.handlers = make(map[string]Handler)
	}
	b.handlers[routeName] = handler
}

func (b *Mux) MustHandleStructs(methodPrefix string, structHandlers ...interface{}) {
	if err := b.HandleStructs(methodPrefix, structHandlers...); err != nil {
		panic(err)
	}
}

func (b *Mux) HandleStructs(methodPrefix string, structHandlers ...interface{}) error {
	for _, s := range structHandlers {
		routes, err := StructRoutes(methodPrefix, s)
		if err != nil {
			return err
		}
		b.HandleRoutes(routes...)
	}
	return nil
}

func (r *Mux) HandleRaw(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
	jsonAPI := resolveJSON(r.JSON)
	iter := jsonAPI.BorrowIterator(input)
	defer jsonAPI.ReturnIterator(iter)
	routeName := iter.ReadObject()
	payload := iter.SkipAndReturnBytes()
	if handler, ok := r.handlers[routeName]; ok {
		reply, err := handler.HandleRaw(ctx, payload)
		if err != nil {
			return nil, NewRouteError(routeName, err)
		}
		return reply, nil
	}
	if notFound := r.NotFound; notFound != nil {
		return notFound.HandleRaw(ctx, input)
	}
	return nil, NewRouteError(routeName, errors.WithStack(ErrRouteNotFound))
}

const DefaultHandlerPrefix = "Handle"

// ErrRouteNotFound is a well-known error that a route was not found.
var ErrRouteNotFound = fmt.Errorf(`route not found`)

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
