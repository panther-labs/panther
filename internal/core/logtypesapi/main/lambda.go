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
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/lambdamux"
)

var config = struct {
	Debug             bool
	LogTypesTableName string `required:"true" split_words:"true"`
}{}

func main() {
	envconfig.MustProcess("", &config)

	logger := lambdalogger.Config{
		Debug:     config.Debug,
		Namespace: "api",
		Component: "logtypes",
	}.MustBuild()

	// Syncing the zap.Logger always results in Lambda errors. Commented code kept as a reminder.
	// defer logger.Sync()

	api := logtypesapi.API{
		ExternalAPI: &logtypesapi.ExternalAPIDynamoDB{
			DB:        dynamodb.New(session.Must(session.NewSession())),
			TableName: config.LogTypesTableName,
		},
		// Use the default registry with all available log types
		NativeLogTypes: registry.AvailableLogTypes,
	}

	mux := lambdamux.Mux{}
	mux.MustHandleStructs("", api)

	// Adds logger to lambda context with a Lambda request ID field
	handler := lambdamux.WithLogger(logger, &mux)

	if config.Debug {
		// Adds debug that always logs input/output
		handler = lambdamux.Debug(handler)
	}

	lambda.Start(handler)
}
