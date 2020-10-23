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
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
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

func HandleCreateTablesMessage(ctx context.Context, msg *CreateTablesMessage) error {
	for _, logType := range msg.LogTypes {
		entry, err := logtypesResolver.Resolve(ctx, logType)
		if err != nil {
			return err
		}
		if entry == nil {
			return errors.Errorf("unresolved log type %q", logType)
		}
		meta := entry.GlueTableMeta()
		// NOTE: This function updates all logtype-related tables, not only the processed log tables
		if _, err := gluetables.CreateOrUpdateGlueTables(glueClient, config.ProcessedDataBucket, meta); err != nil {
			return errors.Wrapf(err, "failed to update tables for log type %q", logType)
		}
	}
	// update the views with the new tables
	availableLogTypes, err := listAvailableLogTypes(ctx)
	if err != nil {
		return err
	}
	deployedLogTypes, err := gluetables.DeployedLogTypes(ctx, glueClient, availableLogTypes)
	if err != nil {
		return err
	}
	deployedLogTables, err := logtypes.ResolveTables(ctx, logtypesResolver, deployedLogTypes...)
	if err != nil {
		return err
	}
	// update the views
	if err := athenaviews.CreateOrReplaceViews(athenaClient, deployedLogTables); err != nil {
		return errors.Wrap(err, "failed to update athena views")
	}
	return nil
}
