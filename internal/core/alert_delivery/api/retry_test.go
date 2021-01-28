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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestRetry(t *testing.T) {
	mockSQS := &testutils.SqsMock{}
	sqsClient = mockSQS

	alert := sampleAlert()
	alerts := []*deliverymodel.Alert{alert, alert, alert}
	queueURL := "sqs-url"

	body, err := jsoniter.MarshalToString(alert)
	require.NoError(t, err)

	input := &sqs.SendMessageBatchInput{
		Entries: []*sqs.SendMessageBatchRequestEntry{
			{
				DelaySeconds: aws.Int64(int64(5)),
				Id:           aws.String("0"),
				MessageBody:  aws.String(body),
			},
			{
				DelaySeconds: aws.Int64(int64(5)),
				Id:           aws.String("1"),
				MessageBody:  aws.String(body),
			},
			{
				DelaySeconds: aws.Int64(int64(5)),
				Id:           aws.String("2"),
				MessageBody:  aws.String(body),
			},
		},
		QueueUrl: aws.String(queueURL),
	}

	mockSQS.On("SendMessageBatch", input).Return(&sqs.SendMessageBatchOutput{}, nil).Once()
	retry(alerts, queueURL, 5, 6)
	mockSQS.AssertExpectations(t)
}
