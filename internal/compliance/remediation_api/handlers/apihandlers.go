package handlers

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

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"

	"github.com/panther-labs/panther/internal/compliance/remediation_api/remediation"
)

var (
	sqsQueueURL = os.Getenv("SQS_QUEUE_URL")

	awsSession                        = session.Must(session.NewSession())
	sqsClient  sqsiface.SQSAPI        = sqs.New(awsSession)
	invoker    remediation.InvokerAPI = remediation.NewInvoker(session.Must(session.NewSession()))
)

// API has all of the handlers as receiver methods
type API struct{}
