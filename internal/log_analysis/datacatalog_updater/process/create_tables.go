package process

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
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
)

// CreateTablesMessage is the event that triggers the creation of Glue tables/views for logtypes.
type CreateTablesMessage struct {
	LogTypes []string
}

// CreateTableMessageAttribute is the SQS message attribute for the CreateTablesMessage.
var CreateTableMessageAttribute = sqs.MessageAttributeValue{
	DataType:    aws.String("String"),
	StringValue: aws.String("CreateTables"),
}

func (m CreateTablesMessage) Send(sqsClient sqsiface.SQSAPI, queueURL string) error {
	marshalled, err := jsoniter.MarshalToString(m)
	if err != nil {
		return err
	}

	sqsInput := sqs.SendMessageInput{
		MessageBody: &marshalled,
		QueueUrl:    &queueURL,
		MessageAttributes: map[string]*sqs.MessageAttributeValue{
			PantherMessageType: &CreateTableMessageAttribute,
		},
	}
	_, err = sqsClient.SendMessage(&sqsInput)
	if err != nil {
		return errors.Wrapf(err, "failed to send message to SQS queue %s", queueURL)
	}
	return nil
}

func HandleCreateTablesMessage(msg CreateTablesMessage) error {
	for _, logType := range msg.LogTypes {
		_, err := gluetables.CreateOrUpdateGlueTablesForLogType(glueClient, logType, config.ProcessedDataBucket)
		if err != nil {
			return errors.Wrapf(err, "failed to create/update glue table for log type %s", logType)
		}
	}
	// update the views with the new tables
	err := athenaviews.CreateOrReplaceViews(glueClient, athenaClient)
	if err != nil {
		return errors.Wrap(err, "failed to create/replace views")
	}
	return nil
}
