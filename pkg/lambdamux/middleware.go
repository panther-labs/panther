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
	"errors"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"
)

func Debug(handler Handler) Handler {
	return HandlerFunc(func(ctx context.Context, input json.RawMessage) (output json.RawMessage, err error) {
		logger := L(ctx)
		if logger == nil {
			logger = zap.L()
		}
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

var zapContextKey = &struct{}{}

func ContextWithLogger(ctx context.Context, logger *zap.Logger) context.Context {
	if logger == nil {
		logger = zap.L()
	}
	// Add lambda fields to the logger
	if ctx, ok := lambdacontext.FromContext(ctx); ok {
		logger = logger.With(
			zap.String(`aws_request_id`, ctx.AwsRequestID),
			zap.String(`aws_lambda_arn`, ctx.InvokedFunctionArn),
		)
	}
	return context.WithValue(ctx, zapContextKey, logger)
}

var nopLogger = zap.NewNop()

func L(ctx context.Context) *zap.Logger {
	if logger, ok := ctx.Value(zapContextKey).(*zap.Logger); ok {
		return logger
	}
	return nopLogger
}

func WithLogger(logger *zap.Logger, handler Handler) Handler {
	return HandlerFunc(func(ctx context.Context, input json.RawMessage) (output json.RawMessage, err error) {
		ctx = ContextWithLogger(ctx, logger)
		output, err = handler.HandleRaw(ctx, input)
		return
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
