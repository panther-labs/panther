package sqsbatch

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
)

func ReceiveMessage(sqsClient sqsiface.SQSAPI, queueURL string, waitTimeSeconds int64) (messages []*sqs.Message,
	messageReceipts []*string, err error) {

	receiveMessageOutput, err := sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
		WaitTimeSeconds:     aws.Int64(waitTimeSeconds), // wait this long UNLESS MaxNumberOfMessages read
		MaxNumberOfMessages: aws.Int64(maxMessages),     // max size allowed
		QueueUrl:            aws.String(queueURL),
	})
	if err != nil {
		err = errors.Wrapf(err, "failure receiving messages from %s", queueURL)
		return nil, nil, err
	}

	messageReceipts = make([]*string, len(receiveMessageOutput.Messages))
	for i := range receiveMessageOutput.Messages {
		messageReceipts[i] = receiveMessageOutput.Messages[i].ReceiptHandle
	}

	return receiveMessageOutput.Messages, messageReceipts, err
}
