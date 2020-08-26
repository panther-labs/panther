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

import (
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/pkg/lambdalogger"
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
	logger := lambdalogger.Config{
		Debug:     config.Debug,
		Namespace: "api",
		Component: "logtypes",
	}.MustBuild()

	// Syncing the zap.Logger always results in Lambda errors. Commented code kept as a reminder.
	// defer logger.Sync()

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

	// Adds logger to lambda context with a Lambda request ID field
	handler := lambdamux.WithLogger(logger, &mux)

	if config.Debug {
		// Adds debug that always logs input/output
		handler = lambdamux.Debug(handler)
	}

	lambda.Start(handler)
}
