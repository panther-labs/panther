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
	"errors"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

const DefaultHandlerPrefix = "Invoke"

// Handler is identical to lambda.Handler.
type Handler interface {
	Invoke(ctx context.Context, payload []byte) ([]byte, error)
}

// HandlerFunc is a function implementing Handler
type HandlerFunc func(ctx context.Context, payload []byte) ([]byte, error)

var _ Handler = (HandlerFunc)(nil)

// Invoke implements lambda.Handler
func (f HandlerFunc) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	return f(ctx, payload)
}

type RouteHandler interface {
	Handler
	Route() string
}

// ErrNotFound is a well-known error that a route was not found.
// Using std errors.New here since we don't want a stack
var ErrNotFound = errors.New(`route not found`)

// RouteError is the error implemented by errors returned from a route handler
type RouteError interface {
	error
	Route() string
}

var defaultJSON = jsoniter.ConfigCompatibleWithStandardLibrary

func resolveJSON(api jsoniter.API) jsoniter.API {
	if api != nil {
		return api
	}
	return defaultJSON
}

func IgnoreCase(name string) string {
	return strings.ToUpper(name)
}
