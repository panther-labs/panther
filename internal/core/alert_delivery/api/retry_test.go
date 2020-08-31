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
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/assert"

	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
)

type mockSQSClient struct {
	sqsiface.SQSAPI
	err bool
}

var sqsMessages int // store number of messages here for tests to verify

func (m mockSQSClient) SendMessageBatch(input *sqs.SendMessageBatchInput) (*sqs.SendMessageBatchOutput, error) {
	if m.err {
		return nil, errors.New("internal service error")
	}
	sqsMessages = len(input.Entries)
	return &sqs.SendMessageBatchOutput{
		Successful: make([]*sqs.SendMessageBatchResultEntry, len(input.Entries)),
	}, nil
}

func TestRetry(t *testing.T) {
	mockClient := &mockOutputsClient{}
	sqsClient = &mockSQSClient{}
	os.Setenv("ALERT_QUEUE_URL", "sqs.url")
	os.Setenv("MIN_RETRY_DELAY_SECS", "10")
	os.Setenv("MAX_RETRY_DELAY_SECS", "30")
	alert := sampleAlert()
	alerts := []*deliveryModels.Alert{alert, alert, alert}
	sqsMessages = 0
	retry(alerts)
	assert.Equal(t, 3, sqsMessages)
	mockClient.AssertExpectations(t)
}
