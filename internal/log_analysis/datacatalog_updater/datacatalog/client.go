package datacatalog

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

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

type Client struct {
	QueueURL string
	SQSAPI   sqsiface.SQSAPI
}

func (c *Client) SendSyncDatabasePartitions(ctx context.Context, event *SyncDatabasePartitionsEvent) error {
	syncEvent := *event
	syncEvent.TraceID = traceIDFromContext(ctx, syncEvent.TraceID)
	return sendEvent(ctx, c.SQSAPI, c.QueueURL, sqsTask{
		SyncDatabasePartitions: &syncEvent,
	})
}

func traceIDFromContext(ctx context.Context, traceID string) string {
	if traceID == "" {
		if lambdaCtx, ok := lambdacontext.FromContext(ctx); ok {
			return lambdaCtx.AwsRequestID
		}
	}
	return traceID
}

func (c *Client) SendSyncDatabase(ctx context.Context, traceID string, requiredLogTypes []string) error {
	return sendEvent(ctx, c.SQSAPI, c.QueueURL, sqsTask{
		SyncDatabase: &SyncDatabaseEvent{
			TraceID:          traceIDFromContext(ctx, traceID),
			RequiredLogTypes: requiredLogTypes,
		},
	})
}

func (c *Client) SendCreateTablesForLogTypes(ctx context.Context, logTypes ...string) error {
	return sendEvent(ctx, c.SQSAPI, c.QueueURL, sqsTask{
		CreateTables: &CreateTablesEvent{
			LogTypes: logTypes,
		},
	})
}
func (c *Client) SendUpdateTableForLogType(ctx context.Context, logType string) error {
	return sendEvent(ctx, c.SQSAPI, c.QueueURL, sqsTask{
		UpdateTable: &UpdateTablesEvent{
			LogType: logType,
			TraceID: traceIDFromContext(ctx, ""),
		},
	})
}

func sendEvent(ctx context.Context, sqsAPI sqsiface.SQSAPI, queueURL string, event sqsTask) error {
	body, err := jsoniter.MarshalToString(event)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal %#v", event)
		return err
	}
	input := &sqs.SendMessageInput{
		MessageBody: aws.String(body),
		QueueUrl:    aws.String(queueURL),
	}
	if _, err := sqsAPI.SendMessageWithContext(ctx, input); err != nil {
		return err
	}
	return nil
}
