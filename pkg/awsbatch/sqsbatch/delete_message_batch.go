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
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"go.uber.org/zap"
)

func DeleteMessageBatch(sqsClient sqsiface.SQSAPI, queueURL string, messageReceipts []*string) {
	// pre-allocate space
	deleteMessageBatchRequestEntries := make([]*sqs.DeleteMessageBatchRequestEntry, maxMessages)
	messagesInBatchCounter := 0
	for i := range deleteMessageBatchRequestEntries {
		deleteMessageBatchRequestEntries[i] = &sqs.DeleteMessageBatchRequestEntry{
			Id: aws.String(strconv.Itoa(i)), // preset ids within batch
		}
	}

	for _, messageReceipt := range messageReceipts {
		deleteMessageBatchRequestEntries = deleteMessageBatchRequestEntries[:messagesInBatchCounter+1] // extend
		deleteMessageBatchRequestEntries[messagesInBatchCounter].ReceiptHandle = messageReceipt        // set
		messagesInBatchCounter++
		if messagesInBatchCounter == maxMessages {
			deleteMessageBatch(sqsClient, queueURL, deleteMessageBatchRequestEntries)
			// reset
			messagesInBatchCounter = 0
			deleteMessageBatchRequestEntries = deleteMessageBatchRequestEntries[:0]
		}
	}
	// the rest
	if messagesInBatchCounter > 0 {
		deleteMessageBatch(sqsClient, queueURL, deleteMessageBatchRequestEntries)
	}
}

func deleteMessageBatch(sqsClient sqsiface.SQSAPI, queueURL string,
	deleteMessageBatchRequestEntries []*sqs.DeleteMessageBatchRequestEntry) {

	// NOTE: this is a best effort, and we log any errors. Failed deleted messages will be re-processed
	deleteMessageBatchOutput, err := sqsClient.DeleteMessageBatch(&sqs.DeleteMessageBatchInput{
		Entries:  deleteMessageBatchRequestEntries,
		QueueUrl: &queueURL,
	})
	if err != nil || len(deleteMessageBatchOutput.Failed) > 0 {
		zap.L().Warn("failure deleting sqs messages",
			zap.String("guidance", "failed messages will be reprocessed"),
			zap.String("queueURL", queueURL),
			zap.Int("numberOfFailedMessages", len(deleteMessageBatchOutput.Failed)),
			zap.Int("numberOfSuccessfulMessages", len(deleteMessageBatchOutput.Successful)),
			zap.Error(err))
	}
}
