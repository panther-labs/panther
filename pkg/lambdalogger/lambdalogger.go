package lambdalogger

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

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Well-known fields
const (
	FieldRequestID   = "requestId"
	FieldApplication = "application"
	FieldNamespace   = "namespace"
	FieldComponent   = "component"
)

type Config struct {
	Debug     bool
	Namespace string
	Component string
	Options   []zap.Option
}

func (c Config) MustBuild() (logger *zap.Logger) {
	logger, err := c.Build()
	if err != nil {
		panic(errors.WithStack(err))
	}
	return
}

func (c Config) Build() (*zap.Logger, error) {
	// We do not use zap.NewDevelopmentConfig() (even for DEBUG) because it disables json logging.
	config := zap.NewProductionConfig()
	if c.Debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	config.InitialFields = c.InitialFields()
	return config.Build(c.Options...)
}

func (c *Config) InitialFields() map[string]interface{} {
	fields := map[string]interface{}{
		FieldApplication: Application,
	}
	if c.Namespace != "" {
		fields[FieldNamespace] = c.Namespace
	}
	if c.Component != "" {
		fields[FieldComponent] = c.Component
	}
	return fields
}

type key struct{}

var contextKey = &key{}

func Context(ctx context.Context, logger *zap.Logger) context.Context {
	if logger == nil {
		logger = nopLogger
	}
	// Add lambda fields to the logger
	logger = withLambdaFieldsFromContext(ctx, logger)
	return context.WithValue(ctx, contextKey, logger)
}

func withLambdaFieldsFromContext(ctx context.Context, logger *zap.Logger) *zap.Logger {
	if ctx, ok := lambdacontext.FromContext(ctx); ok {
		logger = logger.With(
			zap.String(FieldRequestID, ctx.AwsRequestID),
		)
	}
	return logger
}

var nopLogger = zap.NewNop()

func FromContext(ctx context.Context) *zap.Logger {
	if logger, ok := ctx.Value(contextKey).(*zap.Logger); ok {
		return logger
	}
	return zap.L()
}

type middleware struct {
	logger  *zap.Logger
	debug   bool
	handler lambda.Handler
}

func (m *middleware) Invoke(ctx context.Context, payload []byte) (reply []byte, err error) {
	logger := m.logger
	if m.debug {
		defer func() {
			logger.Debug(`lambda handler result`,
				zap.ByteString("payload", payload),
				zap.ByteString("reply", reply),
				zap.Error(err),
			)
		}()
	}
	ctx = Context(ctx, logger)
	reply, err = m.handler.Invoke(ctx, payload)
	return
}
func IsDebug(logger *zap.Logger) bool {
	return logger.Core().Enabled(zap.DebugLevel)
}

func Wrap(logger *zap.Logger, handler lambda.Handler) lambda.Handler {
	return &middleware{
		logger:  logger,
		debug:   IsDebug(logger),
		handler: handler,
	}
}
