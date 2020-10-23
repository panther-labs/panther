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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/pkg/box"
)

const (
	// The message type key to be used when sending SQS messages. Use it to distinguish
	// the type of the message payload.
	PantherMessageType = "PantherMessageType"
	lambdaFunctionName = "panther-datacatalog-updater"
)

// DataCatalogEvent is the event that this lambda accepts.
type DataCatalogEvent struct {
	events.SQSEvent
	SyncDatabaseEvent   *SyncEvent
	SyncTablePartitions *SyncTableEvent
}

// InvokeBackgroundSync triggers a database sync in the background.
// The sync is kicked-off using a Lambda call and will be a long running task.
// This function does not wait for it to finish.
// If no TraceID is provided this function will try to use the AWS request id.
func InvokeBackgroundSync(ctx context.Context, lambdaAPI lambdaiface.LambdaAPI, event *SyncEvent) (err error) {
	syncEvent := *event
	if syncEvent.TraceID == "" {
		if lambdaCtx, ok := lambdacontext.FromContext(ctx); ok {
			syncEvent.TraceID = lambdaCtx.AwsRequestID
		}
	}
	return invokeEvent(ctx, lambdaAPI, &DataCatalogEvent{
		SyncDatabaseEvent: &syncEvent,
	})
}

func invokeEvent(ctx context.Context, lambdaAPI lambdaiface.LambdaAPI, event interface{}) error {
	eventJSON, err := jsoniter.Marshal(event)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal %#v", event)
		return err
	}

	resp, err := lambdaAPI.InvokeWithContext(ctx, &lambda.InvokeInput{
		FunctionName:   box.String(lambdaFunctionName),
		Payload:        eventJSON,
		InvocationType: box.String(lambda.InvocationTypeEvent), // don't wait for response
	})
	if err != nil {
		err = errors.Wrapf(err, "failed to invoke %#v", event)
		return err
	}
	if resp.FunctionError != nil {
		err = errors.Errorf("%s: failed to invoke %#v", *resp.FunctionError, event)
		return err
	}

	return nil
}
