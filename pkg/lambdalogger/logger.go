// Package lambdalogger updates the global zap logger for use in a Lambda function.
package lambdalogger

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"
)

// DebugEnabled is true if the DEBUG environment variable is set to true.
var DebugEnabled = strings.ToLower(os.Getenv("DEBUG")) == "true"

func init() {
	if !DebugEnabled {
		// Swagger HTTP clients log in DEBUG mode if the variable exists with any non-empty value.
		// https://github.com/go-openapi/runtime/blob/master/logger/logger.go#L11
		if err := os.Setenv("DEBUG", ""); err != nil {
			log.Panic("failed to reset DEBUG environment variable: " + err.Error())
		}
	}
}

// ConfigureGlobal adds the Lambda request ID to the global zap logger.
//
// To add fields to every log message, include them in initialFields (the requestID is added for you).
//
// Returns parsed Lambda context, global zap logger.
func ConfigureGlobal(
	ctx context.Context,
	initialFields map[string]interface{},
) (*lambdacontext.LambdaContext, *zap.Logger) {

	lc, ok := lambdacontext.FromContext(ctx)
	if !ok {
		log.Panicf("failed to load Lambda context %+v", ctx)
	}

	// Use the same structure for all log messages so we can apply consistent metric filters.
	// We do not use zap.NewDevelopmentConfig() (even for DEBUG) because it disables json logging.
	config := zap.NewProductionConfig()

	if DebugEnabled {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	if initialFields == nil {
		config.InitialFields = map[string]interface{}{"requestId": lc.AwsRequestID}
	} else {
		initialFields["requestId"] = lc.AwsRequestID
		config.InitialFields = initialFields
	}

	// Log messages already show the line number, we rarely if ever need the full stack trace.
	// Developers can always manually log a stack trace if they need one.
	config.DisableStacktrace = true

	logger, err := config.Build()
	if err != nil {
		log.Panic("failed to build zap logger: " + err.Error())
	}

	zap.ReplaceGlobals(logger)
	return lc, logger
}
