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
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/lambdalogger"
)

func Debug(handler Handler) Handler {
	return HandlerFunc(func(ctx context.Context, input json.RawMessage) (output json.RawMessage, err error) {
		logger := lambdalogger.FromContext(ctx)
		defer func() {
			logger.Debug(`lambda handler result`,
				zap.ByteString("input", input),
				zap.ByteString("output", output),
				zap.Error(err),
			)
		}()
		output, err = handler.HandleRaw(ctx, input)
		return
	})
}

func NotFound(handler, notFound Handler) Handler {
	if notFound == nil {
		return handler
	}
	return HandlerFunc(func(ctx context.Context, event json.RawMessage) (json.RawMessage, error) {
		reply, err := handler.HandleRaw(ctx, event)
		if err != nil && errors.Is(err, ErrRouteNotFound) {
			return notFound.HandleRaw(ctx, event)
		}
		return reply, err
	})
}

func WithLogger(logger *zap.Logger, handler Handler) Handler {
	return HandlerFunc(func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		ctx = lambdalogger.Context(ctx, logger)
		return handler.HandleRaw(ctx, input)
	})
}

func Recover(onPanic func(p interface{}) (json.RawMessage, error), handler Handler) Handler {
	if onPanic == nil {
		return handler
	}
	return HandlerFunc(func(ctx context.Context, input json.RawMessage) (output json.RawMessage, err error) {
		defer func() {
			if p := recover(); p != nil {
				output, err = onPanic(p)
			}
		}()
		output, err = handler.HandleRaw(ctx, input)
		return
	})
}

func CacheProxy(maxAge time.Duration, handler Handler) Handler {
	if maxAge <= 0 {
		return handler
	}
	type cacheEntry struct {
		Output    json.RawMessage
		UpdatedAt time.Time
	}
	cache := map[string]*cacheEntry{}
	var lastInsertAt time.Time
	return HandlerFunc(func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		entry, ok := cache[string(input)]
		if ok && time.Since(entry.UpdatedAt) < maxAge {
			return entry.Output, nil
		}
		output, err := handler.HandleRaw(ctx, input)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		// Reset the whole cache if last insert was too old to avoid memory leaks
		if time.Since(lastInsertAt) > maxAge {
			cache = map[string]*cacheEntry{}
			lastInsertAt = now
		}
		cache[string(input)] = &cacheEntry{
			Output:    output,
			UpdatedAt: now,
		}
		return output, nil
	})
}
