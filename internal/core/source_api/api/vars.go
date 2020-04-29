package api

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
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"

	"github.com/panther-labs/panther/internal/core/source_api/ddb"
)

var (
	db                                      = ddb.New(tableName)
	sess                                    = session.Must(session.NewSession())
	sqsClient               sqsiface.SQSAPI = sqs.New(sess)
	maxElapsedTime                          = 5 * time.Second
	snapshotPollersQueueURL                 = os.Getenv("SNAPSHOT_POLLERS_QUEUE_URL")
	logProcessorQueueURL                    = os.Getenv("LOG_PROCESSOR_QUEUE_URL")
	logProcessorQueueArn                    = os.Getenv("LOG_PROCESSOR_QUEUE_ARN")
	tableName                               = os.Getenv("TABLE_NAME")
)

// API provides receiver methods for each route handler.
type API struct{}
