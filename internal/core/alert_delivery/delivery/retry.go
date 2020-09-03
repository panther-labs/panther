package delivery

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
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const maxSQSBackoff = 30 * time.Second

// Generate a random int between lower (inclusive) and upper (exclusive).
func randomInt(lower, upper int) int {
	return rand.Intn(upper-lower) + lower // #nosec (don't need cryptographic randomness for random retry)
}

// retry a batch of failed outputs by putting them all back on the queue with random delays.
func retry(alerts []*models.Alert) {
	zap.L().Warn("queueing failed alerts for future retry", zap.Int("failedAlerts", len(alerts)))
	input := &sqs.SendMessageBatchInput{
		Entries:  make([]*sqs.SendMessageBatchRequestEntry, len(alerts)),
		QueueUrl: aws.String(os.Getenv("ALERT_QUEUE_URL")),
	}

	rand.Seed(time.Now().UnixNano())
	minDelaySeconds := mustParseInt(os.Getenv("MIN_RETRY_DELAY_SECS"))
	maxDelaySeconds := mustParseInt(os.Getenv("MAX_RETRY_DELAY_SECS"))

	for i, alert := range alerts {
		body, err := jsoniter.MarshalToString(alert)
		if err != nil {
			zap.L().Panic("error encoding alert as JSON", zap.Error(err))
		}

		input.Entries[i] = &sqs.SendMessageBatchRequestEntry{
			DelaySeconds: aws.Int64(int64(randomInt(minDelaySeconds, maxDelaySeconds))),
			Id:           aws.String(strconv.Itoa(i)),
			MessageBody:  aws.String(body),
		}
	}

	if _, err := sqsbatch.SendMessageBatch(getSQSClient(), maxSQSBackoff, input); err != nil {
		zap.L().Error("unable to retry failed alerts", zap.Error(err))
	}
}
