// Package lambdalogger updates the global zap logger for use in a Lambda function.
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
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"
)

const Application = "panther" // tag all logs with "application" -> "panther" (used for audit)

// DebugEnabled is true if the DEBUG environment variable is set to true.
var DebugEnabled = strings.ToLower(os.Getenv("DEBUG")) == "true"

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

	// always tag with requestId and application
	if initialFields == nil {
		config.InitialFields = map[string]interface{}{
			FieldRequestID:   lc.AwsRequestID,
			FieldApplication: Application,
		}
	} else {
		initialFields[FieldRequestID] = lc.AwsRequestID
		initialFields[FieldApplication] = Application
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
