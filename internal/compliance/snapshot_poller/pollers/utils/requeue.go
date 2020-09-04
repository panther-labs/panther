package utils

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
)

// SQS imposed maximum message delay
const MaxRequeueDelaySeconds = 900

var queueURL = os.Getenv("SNAPSHOT_QUEUE_URL")

// Requeue sends a scan request back to the poller input queue
func Requeue(scanRequest poller.ScanMsg, delay int64) error {
	body, err := jsoniter.MarshalToString(scanRequest)
	if err != nil {
		return errors.Wrapf(err, "unable to marshal requeue request: %v", scanRequest)
	}

	if delay > MaxRequeueDelaySeconds {
		delay = MaxRequeueDelaySeconds
	}

	zap.L().Debug(
		"initiating scan re-queue",
		zap.Int64("delaySeconds", delay),
		zap.String("requeueRequest", body),
	)

	sqsClient := sqs.New(session.Must(session.NewSession()))
	_, err = sqsClient.SendMessage(
		&sqs.SendMessageInput{
			MessageBody:  aws.String(body),
			QueueUrl:     &queueURL,
			DelaySeconds: aws.Int64(delay),
		})
	if err != nil {
		return errors.Wrapf(err, "scan re-queueing failed: %v", scanRequest)
	}
	return nil
}
