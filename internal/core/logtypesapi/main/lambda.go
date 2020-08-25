package main

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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/pkg/lambdamux"
)

var config = struct {
	Debug          bool
	LogTypesMaxAge time.Duration `split_words:"true"`
	logtypesapi.Config
}{}

func init() {
	envconfig.MustProcess("", &config)
}

func main() {
	logger := mustBuildLogger()
	// nolint: errcheck
	defer logger.Sync()

	logger = logger.With(
		zap.String(`namespace`, `api`),
		zap.String(`component`, `logtypes`),
	)

	mux := lambdamux.Mux{}
	if maxAge := config.LogTypesMaxAge; maxAge > 0 {
		// Cache results of ListAvailableLogTypes
		mux.Decorate = func(routeName string, handler lambdamux.Handler) lambdamux.Handler {
			switch routeName {
			case "ListAvailableLogTypes":
				return lambdamux.CacheProxy(maxAge, handler)
			default:
				return handler
			}
		}
	}

	api := logtypesapi.BuildAPI(&config.Config)
	mux.MustHandleStructs("", api)

	handler := lambdamux.WithLogger(logger, &mux)

	if config.Debug {
		handler = lambdamux.Debug(handler)
	}

	lambda.Start(handler)
}

func mustBuildLogger() (logger *zap.Logger) {
	var err error
	if config.Debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		panic(errors.Wrap(err, "failed to initialize logger"))
	}
	return
}
