package common

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
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/oplog"
)

// labels for oplog
const (
	OpLogNamespace  = "log_analysis"
	OpLogComponent  = "log_processor"
	OpLogServiceDim = "service"
)

var (
	OpLogManager = oplog.NewManager(OpLogNamespace, OpLogComponent)

	// cross cutting dimensions

	OpLogLambdaServiceDim    = zap.String(OpLogServiceDim, "lambda")
	OpLogS3ServiceDim        = zap.String(OpLogServiceDim, "s3")
	OpLogSNSServiceDim       = zap.String(OpLogServiceDim, "sns")
	OpLogProcessorServiceDim = zap.String(OpLogServiceDim, "processor")
	OpLogGlueServiceDim      = zap.String(OpLogServiceDim, "glue")

	/*
			  Example CloudWatch Insight queries this structure enables:

			  -- show latest activity
			  filter namespace="Panther" and component="LogProcessor"
				| fields @timestamp, operation, stats.LogType, stats.LogLineCount, stats.BytesProcessedCount, stats.EventCount,
		                   stats.SuccessfullyClassifiedCount, stats.ClassificationFailureCount, error
				| sort @timestamp desc
			    | limit 200

			  -- show latest errors
			  filter namespace="Panther" and component="LogProcessor"
			  | filter level='error'
			  | fields @timestamp, operation, stats.LogType, stats.LogLineCount, stats.BytesProcessedCount, stats.EventCount,
		                   stats.SuccessfullyClassifiedCount, stats.ClassificationFailureCount, error
			  | sort @timestamp desc
			  | limit 200

			  -- show all sns activity
			  filter namespace="Panther" and component="LogProcessor"
			  | filter ExternalAPI='sns'
			  | fields @timestamp, topicArn
			  | sort @timestamp desc
			  | limit 200

			   -- show all s3 activity
			   filter namespace="Panther" and component="LogProcessor"
			   | filter ExternalAPI='s3'
			   | fields @timestamp, bucket, key
			   | sort @timestamp desc
			   | limit 200

	*/

)
