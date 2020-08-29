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
	goerr "errors"

	"github.com/aws/aws-lambda-go/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/pkg/x/lambdamux/internal"
)

// ErrNotFound is a well-known error that a route was not found.
// Using std errors.New here since we don't want a stack
var ErrNotFound = goerr.New(`route not found`)

// Mux dispatches handling of a Lambda events
type Mux struct {
	Rename           func(name string) (key string)
	Decorate         func(key string, handler lambda.Handler) lambda.Handler
	Demux            Demux
	JSON             jsoniter.API
	Validate         func(payload interface{}) error
	IgnoreDuplicates bool

	handlers map[string]lambda.Handler
}

// Handlers returns all handlers added to the mux.
func (m *Mux) Handlers() (handlers []lambda.Handler) {
	if len(m.handlers) == 0 {
		return
	}
	handlers = make([]lambda.Handler, 0, len(m.handlers))
	for _, handler := range m.handlers {
		handlers = append(handlers, handler)
	}
	return
}

// MustHandleMethods add all routes from a struct to the Mux or panics.
// It overrides previously defined routes *without* an error.
func (m *Mux) MustHandleMethods(receivers ...interface{}) {
	if err := m.HandleMethodsPrefix("", receivers...); err != nil {
		panic(err)
	}
}

// HandleMethodsPrefix add all routes from a struct to the Mux.
// It fails if a method does not meet the signature requirements.
// It overrides previously defined routes *without* an error.
func (m *Mux) HandleMethodsPrefix(prefix string, receivers ...interface{}) error {
	for _, receiver := range receivers {
		routes, err := internal.RouteMethods(prefix, receiver)
		if err != nil {
			return err
		}
		if err := m.handleRoutes(routes...); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mux) handleRoutes(routes ...*internal.Route) error {
	for _, route := range routes {
		name := route.Name()
		handler := route.Handler(m.JSON, m.Validate)
		if err := m.Handle(name, handler); err != nil {
			return err
		}
	}
	return nil
}

// Handle applies any decoration and adds a handler to the mux.
func (m *Mux) Handle(name string, handler lambda.Handler) error {
	key := name
	if m.Rename != nil {
		key = m.Rename(key)
	}
	if key == "" {
		return errors.Errorf("invalid route name %q", name)
	}
	if decorate := m.Decorate; decorate != nil {
		handler = decorate(key, handler)
	}
	if !m.IgnoreDuplicates {
		if _, duplicate := m.handlers[key]; duplicate {
			return errors.Errorf("duplicate route handler for %q", name)
		}
	}
	if m.handlers == nil {
		m.handlers = map[string]lambda.Handler{}
	}
	m.handlers[key] = handler
	return nil
}

func (m *Mux) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	iter := resolveJSON(m.JSON).BorrowIterator(payload)
	defer iter.Pool().ReturnIterator(iter)
	switch next := iter.WhatIsNext(); next {
	case jsoniter.ObjectValue:
		p, name := m.demux(iter, payload)
		if err := iter.Error; err != nil {
			return nil, errors.Wrap(err, `invalid JSON payload`)
		}
		handler, err := m.Get(name)
		if err != nil {
			return nil, err
		}
		return handler.Invoke(ctx, p)
	case jsoniter.ArrayValue:
		b := borrowBatch()
		defer b.Recycle()
		if err := b.ReadJobs(m, iter); err != nil {
			return nil, err
		}
		return m.runBatch(ctx, b)
	default:
		return nil, errors.Wrapf(ErrNotFound, `invalid JSON payload %q`, next)
	}
}

var defaultDemux = &demuxKeyValue{}

func (m *Mux) demux(iter *jsoniter.Iterator, payload []byte) ([]byte, string) {
	if m.Demux != nil {
		return m.Demux.demux(iter, payload)
	}
	return defaultDemux.demux(iter, payload)
}

func (m *Mux) Get(name string) (lambda.Handler, error) {
	if name == "" {
		return nil, errors.Wrap(ErrNotFound, `invalid payload`)
	}
	key := name
	if m.Rename != nil {
		key = m.Rename(key)
		if key == "" {
			return nil, errors.Wrapf(ErrNotFound, `invalid route key %q`, name)
		}
	}
	if handler, ok := m.handlers[key]; ok {
		return handler, nil
	}
	return nil, errors.WithStack(ErrNotFound)
}
