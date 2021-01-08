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
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	lambdaclient "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/datacatalog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/x/lambdamux"
)

var config = struct {
	Debug               bool
	LogTypesTableName   string `required:"true" split_words:"true"`
	DataCatalogQueueURL string `required:"true" split_words:"true"`
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

	session := session.Must(session.NewSession())
	nativeLogTypes := logtypes.CollectNames(registry.NativeLogTypes())
	// FIXME: uncomment the below line to add the resource history to the of available logTypes and allow rules to target
	// nativeLogTypes = append(nativeLogTypes, logtypes.CollectNames(snapshotlogs.LogTypes())...)
	api := &logtypesapi.LogTypesAPI{
		// Use the default registry with all available log types
		NativeLogTypes: func() []string {
			return nativeLogTypes
		},
		Database: &logtypesapi.DynamoDBLogTypes{
			DB:        dynamodb.New(session),
			TableName: config.LogTypesTableName,
		},
		DataCatalog: datacatalog.Client{
			QueueURL: config.DataCatalogQueueURL,
			SQSAPI:   sqs.New(session),
		},
		LambdaClient: lambdaclient.New(session),
	}

	validate := validator.New()

	mux := lambdamux.Mux{
		// use case-insensitive route matching
		RouteName: lambdamux.IgnoreCase,
		Validate:  validate.Struct,
		// We want the API to return errors as something to display to the user.
		// We decorate each route handler so that all errors are properly encapsulated as APIError and logged if needed
		// Any APIErrors returned by the routes are not logged as these were properly handled by the API
		// All errors are return as `{"error": {"code": "ERR_CODE", "message": "ERROR_MSG"}}` in the reply.
		Decorate: func(name string, handler lambdamux.Handler) lambdamux.Handler {
			return lambdamux.HandlerFunc(func(ctx context.Context, payload []byte) ([]byte, error) {
				reply, err := handler.Invoke(ctx, payload)
				if err != nil {
					apiErr := logtypesapi.AsAPIError(err)
					// If the error was not an APIError we log it.
					if apiErr == nil {
						// Add the route name as "action" field
						lambdalogger.FromContext(ctx).Error("action failed", zap.String("action", name), zap.Error(err))
						// We wrap it as APIError to be serialized
						apiErr = logtypesapi.WrapAPIError(err)
					}
					return jsoniter.Marshal(logtypesapi.ErrorReply{
						Error: apiErr,
					})
				}
				return reply, nil
			})
		},
	}

	mux.MustHandleMethods(api)

	// Adds logger to lambda context with a Lambda request ID field and debug output
	handler := lambdalogger.Wrap(logger, &mux)

	lambda.StartHandler(handler)
}
