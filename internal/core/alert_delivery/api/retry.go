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
	"math/rand"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const maxSQSBackoff = 30 * time.Second

// retry - sends a list of alerts back to the queue with random delays.
func retry(alerts []*deliverymodel.Alert, queueURL string, minDelaySecs int, maxDelaySecs int) {
	if len(alerts) == 0 {
		return
	}

	// Set a new seed on every invocation
	rand.Seed(time.Now().UnixNano())

	input := createInput(alerts, queueURL, minDelaySecs, maxDelaySecs)
	sendToSQS(input)
}

func createInput(alerts []*deliverymodel.Alert, queueURL string, minDelaySecs int, maxDelaySecs int) *sqs.SendMessageBatchInput {
	return &sqs.SendMessageBatchInput{
		Entries:  createEntries(alerts, minDelaySecs, maxDelaySecs),
		QueueUrl: aws.String(queueURL),
	}
}

func createEntries(alerts []*deliverymodel.Alert, minRetryDelay int, maxRetryDelay int) []*sqs.SendMessageBatchRequestEntry {
	entries := []*sqs.SendMessageBatchRequestEntry{}
	for i, alert := range alerts {
		body, err := jsoniter.MarshalToString(alert)
		if err != nil {
			zap.L().Panic("error encoding alert as JSON", zap.Error(err))
		}
		delay := randomInt64n(minRetryDelay, maxRetryDelay)
		entries = append(entries, createEntry(body, i, delay))
	}
	return entries
}

func createEntry(messageBody string, index int, delaySeconds int64) *sqs.SendMessageBatchRequestEntry {
	return &sqs.SendMessageBatchRequestEntry{
		Id:           aws.String(strconv.Itoa(index)),
		DelaySeconds: aws.Int64(delaySeconds),
		MessageBody:  aws.String(messageBody),
	}
}

// Generate a random int between lower (inclusive) and upper (exclusive).
func randomInt64n(min int, max int) int64 {
	return rand.Int63n(int64(max)-int64(min)) + int64(min) // nolint:gosec
}

func sendToSQS(input *sqs.SendMessageBatchInput) {
	if _, err := sqsbatch.SendMessageBatch(sqsClient, maxSQSBackoff, input); err != nil {
		zap.L().Error("unable to retry failed alerts", zap.Error(err))
	}
}
